using KeePassWinHello;

using System;
using System.Collections;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Windows.Security.Cryptography.Core;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;
using Windows.Storage;
using Windows.System;
using Windows.UI.Popups;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;
using static WpfApp3.MyWindowsStorage;

namespace WpfApp3
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        MyWindowsStorage storage;
        public MainWindow()
        {
            InitializeComponent();
            storage = new MyWindowsStorage();                 
        }
        //Метод сохраняющий строку из Текстбокса в само хранилище при этом создавая ключ
        //Будет использоваться в настройках Passwarden и будет доступен только тем у кого включен WindowsHello
        //При этом используется шифрование из примера. В Passwarden буду сохранять туда RecoveryKey.
        //Для самого Recovery думаю использовать DisposableString. Реализую уже по примеру из PW 
        private async void ProtectDataClick(object sender, RoutedEventArgs e)
        {
            MyWindowsStorage.CreatePersistentKey(true).Dispose();
            byte[] bytes = storage.Encrypt(Encoding.ASCII.GetBytes(txtToSave.Text), false);
            storage.AddOrUpdate("secret", bytes);

            //Maybe cleaning array
            //Array.Clear(bytes);
        }
        //Метод получения данных. Будет использоваться при включенном в настройках Windows Hello и при его доступности в ОС при вводе мастер пароля
        //По нему будет происходить вход в приложение
        //Также можно проверить на странице мастер пароля существует ли PersistenKey и валидный ли он. Но нужно предусмотреть уникальность ключей для каждого пользователя
        private async void UnProtectData(object sender, RoutedEventArgs e)
        {
            byte[] bytes;
            storage.TryGetValue("secret", out bytes);
            bytes = storage.PromptToDecrypt(bytes, false);
            txtToShow.Text = System.Text.Encoding.UTF8.GetString(bytes);
            //Maybe cleaning array
            //Array.Clear(bytes);
        }
        //Удаление данных по ключу. Будет использоваться при выключении функции Windows Hello
        private void RemoveData(object sender, RoutedEventArgs e)
        {
            DeletePersistentKey();
            storage.Remove("secret");
        }
        //Настройка видимости контента
        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            //Проверка доступности Windows Hello в ОС 
            bool supported = await KeyCredentialManager.IsSupportedAsync();
            if (supported)
            {
                StackPanel1.Visibility = Visibility.Visible;
                StackPanel2.Visibility = Visibility.Visible;
                StackPanel3.Visibility = Visibility.Collapsed;
            }
            else
            {
                StackPanel1.Visibility = Visibility.Collapsed;
                StackPanel2.Visibility = Visibility.Collapsed;
                StackPanel3.Visibility = Visibility.Visible;
            }
        }
    }

    public class MyWindowsStorage
    {

        public MyWindowsStorage()
        {
            try
            {
                
                SafeNCryptKeyHandle ngcKeyHandle;
                if (!TryOpenPersistentKey(out ngcKeyHandle))
                    throw new AuthProviderKeyNotFoundException("Persistent key does not exist.");

                using (ngcKeyHandle)
                {
                    if (!VerifyPersistentKeyIntegrity(ngcKeyHandle))
                    {
                        ngcKeyHandle.Close();
                        DeletePersistentKey();
                        throw new AuthProviderInvalidKeyException(InvalidatedKeyMessage);
                    }
                }
            }
            catch
            {

            }
        }
        public enum AuthCacheType
        {
            Persistent,
            Local,
        }

        [StructLayout(LayoutKind.Sequential)]
        struct BOOL
        {
            public int Value;
            public bool Result { get { return Value != 0; } }

            public bool ThrowOnError(string debugInfo = "", params int[] ignoredErrors)
            {
                if (!Result)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    if (errorCode != 0 && (ignoredErrors == null || !ignoredErrors.Contains(errorCode)))
                        throw new EnviromentErrorException(debugInfo, errorCode);
                }

                return Result;
            }
        }
        #region Credential Manager API
        private const int ERROR_NOT_FOUND = 0x490;

        private const int CRED_TYPE_GENERIC = 0x1;

        private const int CRED_PERSIST_LOCAL_MACHINE = 0x2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public UInt32 Flags;
            public UInt32 Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public UInt32 CredentialBlobSize;
            public IntPtr CredentialBlob;
            public UInt32 Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;

        }
        [DllImport("Kernel32.dll", EntryPoint = "RtlZeroMemory", SetLastError = false)]
        static extern void ZeroMemory(IntPtr dest, IntPtr size);

        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern BOOL CredDelete(string target, uint type, int reservedFlag);

        [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern BOOL CredEnumerate(string target, uint flags, out uint count, out IntPtr credentialsPtr);

        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern BOOL CredRead(string target, uint type, int reservedFlag, out IntPtr CredentialPtr);

        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern BOOL CredWrite([In] ref CREDENTIAL userCredential, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern BOOL CredFree([In] IntPtr cred);
        #endregion

        private const int _maxBlobSize = 512 * 5;

        public void AddOrUpdate(string dbPath, byte[] protectedKey)
        {
            byte[] data = protectedKey;
            try
            {
                if (data.Length > _maxBlobSize)
                    throw new ArgumentOutOfRangeException("protectedKey", "protectedKey blob has exceeded 2560 bytes");

                var ncred = new CREDENTIAL();
                try
                {
                    ncred.Type = CRED_TYPE_GENERIC;
                    ncred.Persist = CRED_PERSIST_LOCAL_MACHINE;
                    //Подставлю реальный username пользователя
                    ncred.UserName = Marshal.StringToCoTaskMemUni("username");
                    //Можно поставить всё что угодно в качестве пути к бд. Любой набор символов, но должен быть уникальынм для каждого юзера
                    ncred.TargetName = Marshal.StringToCoTaskMemUni("VPNU_" + dbPath);
                    ncred.CredentialBlob = Marshal.AllocCoTaskMem(data.Length);
                    Marshal.Copy(data, 0, ncred.CredentialBlob, data.Length);
                    ncred.CredentialBlobSize = (uint)data.Length;

                    CredWrite(ref ncred, 0).ThrowOnError("CredWrite");
                }
                finally
                {
                    Marshal.FreeCoTaskMem(ncred.UserName);
                    Marshal.FreeCoTaskMem(ncred.TargetName);
                    Marshal.FreeCoTaskMem(ncred.CredentialBlob);
                }
            }
            finally
            {
                //MemUtil.ZeroByteArray(data);
                Array.Clear(data);
               
               
            }
        }
        public bool TryGetValue(string dbPath, out byte[] protectedKey)
        {
            protectedKey = null;
            IntPtr ncredPtr;

            if (!CredRead("VPNU_"+dbPath, CRED_TYPE_GENERIC, 0, out ncredPtr).Result)
            {
                Debug.Assert(Marshal.GetLastWin32Error() == ERROR_NOT_FOUND);
                return false;
            }

            byte[] data = null;
            try
            {
                var ncred = (CREDENTIAL)Marshal.PtrToStructure(ncredPtr, typeof(CREDENTIAL));
                //Тут есть проверка на время хранения данных. Можно указать любой промежуток и настроить это у себя. 
                //Если например данные протухли.
                if (IsExpired(ncred))
                    return false;

                data = new byte[ncred.CredentialBlobSize];
                Marshal.Copy(ncred.CredentialBlob, data, 0, data.Length);

                protectedKey =data;
            }
            catch
            {
                CredDelete("VPNU_" + dbPath, CRED_TYPE_GENERIC, 0);
                throw;
            }
            finally
            {
                //Тут вопрос по очистке данных из памяти. Можно оставить любой вариант
                CredFree(ncredPtr);
                //MemUtil не поддерживается. Пока не разобрался в чем проблема
                //if (data != null)
                //    MemUtil.ZeroByteArray(data);
                //if(data != null)
                //    Array.Clear(data);
            }
            return true;
        }
        
        public void Remove(string dbPath)
        {
            CredDelete("VPNU_"+dbPath, CRED_TYPE_GENERIC, 0).ThrowOnError("CredDelete");
        }
        private bool IsExpired(CREDENTIAL ncred)
        {
            try
            {
                long highDateTime = (long)((uint)ncred.LastWritten.dwHighDateTime) << 32;
                long lowDateTime = (uint)ncred.LastWritten.dwLowDateTime;

                var createdDate = DateTime.FromFileTime(highDateTime | lowDateTime);
                //Время хранения данных
                //if (DateTime.Now - createdDate >= Settings.Instance.InvalidatingTime)
                    return false;
            }
            catch (ArgumentOutOfRangeException)
            {
                return true;
            }

            return false;
        }
        #region CNG key storage provider API
        private const string MS_NGC_KEY_STORAGE_PROVIDER = "Microsoft Passport Key Storage Provider";
        private const string NCRYPT_WINDOW_HANDLE_PROPERTY = "HWND Handle";
        private const string NCRYPT_USE_CONTEXT_PROPERTY = "Use Context";
        private const string NCRYPT_LENGTH_PROPERTY = "Length";
        private const string NCRYPT_KEY_USAGE_PROPERTY = "Key Usage";
        private const string NCRYPT_NGC_CACHE_TYPE_PROPERTY = "NgcCacheType";
        private const string NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED = "NgcCacheTypeProperty";
        private const string NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY = "PinCacheIsGestureRequired";
        private const string BCRYPT_RSA_ALGORITHM = "RSA";
        private const int NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG = 0x00000001;
        private const int NCRYPT_ALLOW_DECRYPT_FLAG = 0x00000001;
        private const int NCRYPT_ALLOW_SIGNING_FLAG = 0x00000002;
        private const int NCRYPT_ALLOW_KEY_IMPORT_FLAG = 0x00000008;
        private const int NCRYPT_PAD_PKCS1_FLAG = 0x00000002;
        private const int NTE_USER_CANCELLED = unchecked((int)0x80090036);
        private const int NTE_NO_KEY = unchecked((int)0x8009000D);
        private const int NTE_BAD_DATA = unchecked((int)0x80090005);
        private const int NTE_BAD_KEYSET = unchecked((int)0x80090016);
        private const int NTE_INVALID_HANDLE = unchecked((int)0x80090026);
        private const int TPM_20_E_HANDLE = unchecked((int)0x8028008B);
        private const int TPM_20_E_SIZE = unchecked((int)0x80280095);
        private const int TPM_20_E_159 = unchecked((int)0x80280159);
        private const int ERROR_CANCELLED = unchecked((int)0x800704C7);

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_STATUS
        {
            public int secStatus;

            /*
            * NTE_BAD_FLAGS
            * NTE_BAD_KEYSET
            * NTE_BAD_KEY_STATE
            * NTE_BUFFER_TOO_SMALL
            * NTE_INVALID_HANDLE
            * NTE_INVALID_PARAMETER
            * NTE_PERM
            * NTE_NO_MEMORY
            * NTE_NOT_SUPPORTED
            * NTE_USER_CANCELLED
            */
            public void ThrowOnError(string name = "", int ignoreStatus = 0)
            {
                if (secStatus >= 0 || secStatus == ignoreStatus)
                    return;

                switch (secStatus)
                {
                    case NTE_USER_CANCELLED:
                        throw new AuthProviderUserCancelledException();
                    case NTE_NO_KEY:
                        throw new AuthProviderKeyNotFoundException();
                    default:
                        throw new AuthProviderSystemErrorException(name, secStatus);
                }
            }
        }

        [DllImport("cryptngc.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NgcGetDefaultDecryptionKeyName(string pszSid, int dwReserved1, int dwReserved2, [Out] out string ppszKeyName);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptOpenStorageProvider([Out] out SafeNCryptProviderHandle phProvider, string pszProviderName, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptOpenKey(SafeNCryptProviderHandle hProvider, [Out] out SafeNCryptKeyHandle phKey, string pszKeyName, int dwLegacyKeySpec, CngKeyOpenOptions dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptCreatePersistedKey(SafeNCryptProviderHandle hProvider,
                                                          [Out] out SafeNCryptKeyHandle phKey,
                                                          string pszAlgId,
                                                          string pszKeyName,
                                                          int dwLegacyKeySpec,
                                                          CngKeyCreationOptions dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern SECURITY_STATUS NCryptFinalizeKey(SafeNCryptKeyHandle hKey, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern SECURITY_STATUS NCryptDeleteKey(SafeNCryptKeyHandle hKey, int flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptGetProperty(SafeNCryptHandle hObject, string pszProperty, ref int pbOutput, int cbOutput, [Out] out int pcbResult, CngPropertyOptions dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptSetProperty(SafeNCryptHandle hObject, string pszProperty, string pbInput, int cbInput, CngPropertyOptions dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptSetProperty(SafeNCryptHandle hObject, string pszProperty, [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput, int cbInput, CngPropertyOptions dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern SECURITY_STATUS NCryptEncrypt(SafeNCryptKeyHandle hKey,
                                               [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                               int cbInput,
                                               IntPtr pvPaddingZero,
                                               [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
                                               int cbOutput,
                                               [Out] out int pcbResult,
                                               int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern SECURITY_STATUS NCryptDecrypt(SafeNCryptKeyHandle hKey,
                                               [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbInput,
                                               int cbInput,
                                               IntPtr pvPaddingZero,
                                               [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
                                               int cbOutput,
                                               [Out] out int pcbResult,
                                               int dwFlags);
        #endregion

        private static string LocalKeyName
        {
            get
            {
                string local, persistent;
                RetrieveKeys(out local, out persistent);
                return local;
            }
        }
        private const string Domain = "Passwarden";
        private const string SubDomain = "Passwarden";
        private const string PersistentName = "Passwarden";
        private static readonly Lazy<string> _currentSID = new Lazy<string>(WindowsIdentity.GetCurrent().User.ToString);
        private static void RetrieveKeys(out string localKey, out string persistentKey)
        {
            NgcGetDefaultDecryptionKeyName(_currentSID.Value, 0, 0, out localKey);
            persistentKey = _currentSID.Value + "//" + Domain + "/" + SubDomain + "/" + PersistentName;

            // It's not expected to use persistent key if local key does not exist
            if (string.IsNullOrEmpty(localKey))
                throw new AuthProviderIsUnavailableException("Windows Hello is not available.");
        }
        private static string PersistentKeyName
        {
            get
            {
                string local, persistent;
                RetrieveKeys(out local, out persistent);
                return persistent;
            }
        }

        private string CurrentKeyName
        {
            get { return LocalKeyName; }
        }
        public AuthCacheType CurrentCacheType { get; private set; } = AuthCacheType.Local;
        private const string InvalidatedKeyMessage = "Persistent key has not met integrity requirements. It might be caused by a spoofing attack. Try to recreate the key.";

        public static bool VerifyPersistentKeyIntegrity(SafeNCryptKeyHandle ngcKeyHandle)
        {
            int pcbResult;
            int keyUsage = 0;
            NCryptGetProperty(ngcKeyHandle, NCRYPT_KEY_USAGE_PROPERTY, ref keyUsage, sizeof(int), out pcbResult, CngPropertyOptions.None).ThrowOnError("NCRYPT_KEY_USAGE_PROPERTY");
            if ((keyUsage & NCRYPT_ALLOW_KEY_IMPORT_FLAG) == NCRYPT_ALLOW_KEY_IMPORT_FLAG)
                return false;

            int cacheType = 0;
            try
            {
                NCryptGetProperty(ngcKeyHandle, NCRYPT_NGC_CACHE_TYPE_PROPERTY, ref cacheType, sizeof(int), out pcbResult, CngPropertyOptions.None).ThrowOnError("NCRYPT_NGC_CACHE_TYPE_PROPERTY");
            }
            catch
            {
                NCryptGetProperty(ngcKeyHandle, NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED, ref cacheType, sizeof(int), out pcbResult, CngPropertyOptions.None).ThrowOnError("NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED");
            }
            if (cacheType != NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG)
                return false;

            return true;
        }
        public byte[] Encrypt(byte[] data, bool retry)
        {
            byte[] cbResult;
            SafeNCryptProviderHandle ngcProviderHandle;
            NCryptOpenStorageProvider(out ngcProviderHandle, MS_NGC_KEY_STORAGE_PROVIDER, 0).ThrowOnError("NCryptOpenStorageProvider");
            using (ngcProviderHandle)
            {
                SafeNCryptKeyHandle ngcKeyHandle;
                NCryptOpenKey(ngcProviderHandle, out ngcKeyHandle, CurrentKeyName, 0, CngKeyOpenOptions.Silent).ThrowOnError("NCryptOpenKey");
                using (ngcKeyHandle)
                {
                    if (CurrentCacheType == AuthCacheType.Persistent && !VerifyPersistentKeyIntegrity(ngcKeyHandle))
                        throw new AuthProviderInvalidKeyException(InvalidatedKeyMessage);

                    int pcbResult;
                    NCryptEncrypt(ngcKeyHandle, data, data.Length, IntPtr.Zero, null, 0, out pcbResult, NCRYPT_PAD_PKCS1_FLAG).ThrowOnError("NCryptEncrypt");

                    cbResult = new byte[pcbResult];
                    NCryptEncrypt(ngcKeyHandle, data, data.Length, IntPtr.Zero, cbResult, cbResult.Length, out pcbResult, NCRYPT_PAD_PKCS1_FLAG).ThrowOnError("NCryptEncrypt");
                    System.Diagnostics.Debug.Assert(cbResult.Length == pcbResult);
                }
            }

            return cbResult;
        }

        public byte[] PromptToDecrypt(byte[] data, bool retry)
        {
            byte[] cbResult;
            SafeNCryptProviderHandle ngcProviderHandle;
            NCryptOpenStorageProvider(out ngcProviderHandle, MS_NGC_KEY_STORAGE_PROVIDER, 0).ThrowOnError("NCryptOpenStorageProvider");
            using (ngcProviderHandle)
            {
                SafeNCryptKeyHandle ngcKeyHandle;
                NCryptOpenKey(ngcProviderHandle, out ngcKeyHandle, CurrentKeyName, 0, CngKeyOpenOptions.None).ThrowOnError("NCryptOpenKey");
                using (ngcKeyHandle)
                {
                    if (CurrentCacheType == AuthCacheType.Persistent && !VerifyPersistentKeyIntegrity(ngcKeyHandle))
                        throw new AuthProviderInvalidKeyException(InvalidatedKeyMessage);

                    //ApplyUIContext(ngcKeyHandle, retry);

                    byte[] pinRequired = BitConverter.GetBytes(1);
                    NCryptSetProperty(ngcKeyHandle, NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY, pinRequired, pinRequired.Length, CngPropertyOptions.None).ThrowOnError("NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY");

                    // The pbInput and pbOutput parameters can point to the same buffer. In this case, this function will perform the decryption in place.
                    cbResult = new byte[data.Length * 2];
                    int pcbResult;
                    NCryptDecrypt(ngcKeyHandle, data, data.Length, IntPtr.Zero, cbResult, cbResult.Length, out pcbResult, NCRYPT_PAD_PKCS1_FLAG).ThrowOnError("NCryptDecrypt");
                    // TODO: secure resize
                    Array.Resize(ref cbResult, pcbResult);
                }
            }

            return cbResult;
        }

        public static SafeNCryptKeyHandle CreatePersistentKey(bool overwriteExisting)
        {
            SafeNCryptProviderHandle ngcProviderHandle;

            NCryptOpenStorageProvider(out ngcProviderHandle, MS_NGC_KEY_STORAGE_PROVIDER, 0).ThrowOnError("NCryptOpenStorageProvider");

            SafeNCryptKeyHandle ngcKeyHandle;
            using (ngcProviderHandle)
            {
                NCryptCreatePersistedKey(ngcProviderHandle,
                            out ngcKeyHandle,
                            BCRYPT_RSA_ALGORITHM,
                            PersistentKeyName,
                            0, overwriteExisting ? CngKeyCreationOptions.OverwriteExistingKey : CngKeyCreationOptions.None
                            ).ThrowOnError("NCryptCreatePersistedKey");

                byte[] lengthProp = BitConverter.GetBytes(2048);
                NCryptSetProperty(ngcKeyHandle, NCRYPT_LENGTH_PROPERTY, lengthProp, lengthProp.Length, CngPropertyOptions.None).ThrowOnError("NCRYPT_LENGTH_PROPERTY");

                byte[] keyUsage = BitConverter.GetBytes(NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG);
                NCryptSetProperty(ngcKeyHandle, NCRYPT_KEY_USAGE_PROPERTY, keyUsage, keyUsage.Length, CngPropertyOptions.None).ThrowOnError("NCRYPT_KEY_USAGE_PROPERTY");

                byte[] cacheType = BitConverter.GetBytes(NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG);
                try
                {
                    NCryptSetProperty(ngcKeyHandle, NCRYPT_NGC_CACHE_TYPE_PROPERTY, cacheType, cacheType.Length, CngPropertyOptions.None).ThrowOnError("NCRYPT_NGC_CACHE_TYPE_PROPERTY");
                }
                catch
                {
                    NCryptSetProperty(ngcKeyHandle, NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED, cacheType, cacheType.Length, CngPropertyOptions.None).ThrowOnError("NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED");
                }

               

                NCryptFinalizeKey(ngcKeyHandle, 0).ThrowOnError("NCryptFinalizeKey");
            }

            return ngcKeyHandle;
        }


        public static void DeletePersistentKey()
        {
            SafeNCryptKeyHandle ngcKeyHandle;
            if (TryOpenPersistentKey(out ngcKeyHandle))
            {
                using (ngcKeyHandle)
                {
                    NCryptDeleteKey(ngcKeyHandle, 0).ThrowOnError("NCryptDeleteKey");
                    ngcKeyHandle.SetHandleAsInvalid();
                }
            }
        }

        public static bool TryOpenPersistentKey(out SafeNCryptKeyHandle ngcKeyHandle)
        {
            SafeNCryptProviderHandle ngcProviderHandle;
            NCryptOpenStorageProvider(out ngcProviderHandle, MS_NGC_KEY_STORAGE_PROVIDER, 0).ThrowOnError("NCryptOpenStorageProvider");

            using (ngcProviderHandle)
            {
                NCryptOpenKey(ngcProviderHandle,
                    out ngcKeyHandle,
                    PersistentKeyName,
                    0, CngKeyOpenOptions.None
                    ).ThrowOnError("NCryptOpenKey", NTE_NO_KEY);
            }

            return ngcKeyHandle != null && !ngcKeyHandle.IsInvalid;
        }
    }



}

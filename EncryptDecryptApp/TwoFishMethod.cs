
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace GeneXus.Encryption
{
    public class TwoFishMethod
    {
        private static RandomNumberGenerator rng;
        public static string AJAX_ENCRYPTION_KEY = "GX_AJAX_KEY";
        public static string AJAX_ENCRYPTION_IV = "GX_AJAX_IV";
        public static string AJAX_SECURITY_TOKEN = nameof(AJAX_SECURITY_TOKEN);
        public static string GX_AJAX_PRIVATE_KEY = "E7C360308E854317711A3D9983B98975";
        public static string GX_AJAX_PRIVATE_IV = "C01D04B1610243D2A2AF23E7952E8B18";
        private static readonly int[] VALID_KEY_LENGHT_IN_BYTES = new int[3]
        {
      32,
      48,
      64
        };
        private const char NULL_CHARACTER = '\0';
        private static int CHECKSUM_LENGTH = 6;
        private static ConcurrentDictionary<string, object> convertedKeys = new ConcurrentDictionary<string, object>();
        private static string serverKey;
        private static string siteKey;
        private static char[] HEX_DIGITS = new char[16]
        {
      '0',
      '1',
      '2',
      '3',
      '4',
      '5',
      '6',
      '7',
      '8',
      '9',
      'A',
      'B',
      'C',
      'D',
      'E',
      'F'
        };
        private static string s_currentDir;

        private static string GX_ENCRYPT_KEYVALUE
        {
            get
            {
                throw new FileNotFoundException("Encryption keys file not found", "application.key or KeyResolver.dll");
            }
        }

        public static string Encrypt64(string value, string key)
        {
            return cryimol.Encrypt64(value, key, false);
        }

        public static string Encrypt64(string value, string key, bool safeEncoding)
        {
            if (!cryimol.IsValidKey(key))
                throw new InvalidKeyException();
            try
            {
                if (string.IsNullOrEmpty(value))
                    return string.Empty;
                byte[] inArray = cryimol.encrypt(Encoding.UTF8.GetBytes(value), cryimol.ConvertedKey(key));
                return safeEncoding ? cryimol.ConvertToBase64Url(inArray) : Convert.ToBase64String(inArray, 0, inArray.Length);
            }
            catch (Exception ex)
            {
                throw new InvalidKeyException();
            }
        }

        private static string InverseKey(string key)
        {
            if (!cryimol.IsValidKey(key))
                throw new InvalidKeyException();
            int num = key.Length / 2;
            return key.Substring(num) + key.Substring(0, num);
        }

        private static bool IsValidKey(string key)
        {
            return !string.IsNullOrEmpty(key) && ((IEnumerable<int>)cryimol.VALID_KEY_LENGHT_IN_BYTES).Contains<int>(key.Length);
        }

        [SecuritySafeCritical]
        private static string ConvertToBase64Url(byte[] value) => Base64UrlEncoder.Encode(value);

        public static string Encrypt(string value, string key, bool inverseKey)
        {
            if (inverseKey)
                key = cryimol.InverseKey(key);
            return cryimol.Encrypt(value, key);
        }

        public static string Encrypt(string value) => cryimol.Encrypt(value, false);

        public static string Encrypt(string value, bool inverseKey)
        {
            string key = cryimol.GetServerKey();
            if (inverseKey)
                key = cryimol.InverseKey(key);
            return cryimol.Encrypt(value, key);
        }

        public static string Encrypt(string value, string key)
        {
            return cryimol.Encrypt64(cryimol.addchecksum(value, cryimol.getCheckSumLength()), key);
        }

        public static string Decrypt(string cfgBuf, string key, bool inverseKey)
        {
            string empty = string.Empty;
            cryimol.Decrypt(ref empty, cfgBuf, inverseKey, key);
            return empty;
        }

        public static string Decrypt(string cfgBuf, string key)
        {
            return cryimol.Decrypt(cfgBuf, key, false);
        }

        public static string Decrypt(string cfgBuf) => cryimol.Decrypt(cfgBuf, false);

        public static string Decrypt(string cfgBuf, bool inverseKey)
        {
            string empty = string.Empty;
            cryimol.Decrypt(ref empty, cfgBuf, inverseKey, (string)null);
            return empty;
        }

        public static bool Decrypt(ref string ret, string cfgBuf)
        {
            return cryimol.Decrypt(ref ret, cfgBuf, false, (string)null);
        }

        private static bool Decrypt(ref string ret, string cfgBuf, bool inverseKey, string key)
        {
            bool flag = false;
            if (string.IsNullOrEmpty(key))
                key = cryimol.GetServerKey();
            if (inverseKey)
                key = cryimol.InverseKey(key);
            string str1 = cryimol.Decrypt64(cfgBuf, key);
            if (str1.Length < 6)
                return flag;
            string str2 = str1.Substring(str1.Length - 6, 6);
            string str3 = str1.Substring(0, str1.Length - 6);
            string str4 = cryimol.CheckSum(str3, 6);
            if (str2 == str4)
            {
                ret = str3;
                flag = true;
            }
            return flag;
        }

        private static object ConvertedKey(string key)
        {
            if (!cryimol.convertedKeys.ContainsKey(key))
                cryimol.convertedKeys.TryAdd(key, Twofish_Algorithm.makeKey(cryimol.convertKey(key)));
            return cryimol.convertedKeys[key];
        }

        private static byte[] convertKey(string a)
        {
            byte[] numArray = new byte[a.Length / 2];
            int index1 = 0;
            int index2 = 0;
            while (index1 < a.Length)
            {
                numArray[index2] = (byte)((uint)cryimol.toHexa(a[index1]) * 16U + (uint)cryimol.toHexa(a[index1 + 1]));
                index1 += 2;
                ++index2;
            }
            return numArray;
        }

        private static byte toHexa(char c)
        {
            if (c >= '0' && c <= '9')
                return (byte)((uint)c - 48U);
            if (c >= 'a' && c <= 'f')
                return (byte)((int)c - 97 + 10);
            if (c >= 'A' && c <= 'F')
                return (byte)((int)c - 65 + 10);
            throw new InvalidKeyException(c.ToString());
        }

        public static string encrypt16(string value, string key) => string.Empty;

        public static string decrypt16(string value, string key) => string.Empty;

        public static string Decrypt64(string value, string key)
        {
            return cryimol.Decrypt64(value, key, false);
        }

        public static string Decrypt64(string value, string key, bool safeEncoding)
        {
            if (string.IsNullOrEmpty(value) || value.Trim().Length == 0)
                return string.Empty;
            if (!cryimol.IsValidKey(key))
                throw new InvalidKeyException();
            value = value.TrimEnd(' ');
            try
            {
                byte[] bytes = !safeEncoding ? cryimol.decrypt(new Base64Decoder(value.ToCharArray()).GetDecoded(), cryimol.ConvertedKey(key)) : cryimol.decrypt(cryimol.ConvertFromBase64Url(value), cryimol.ConvertedKey(key));
                return Encoding.UTF8.GetString(bytes, 0, bytes.Length).TrimEnd(' ');
            }
            catch (Exception ex)
            {
                throw new InvalidKeyException();
            }
        }

        [SecuritySafeCritical]
        private static byte[] ConvertFromBase64Url(string value) => Base64UrlEncoder.DecodeBytes(value);

        public static int getCheckSumLength() => cryimol.CHECKSUM_LENGTH;

        public static string GetServerKey()
        {
            if (cryimol.serverKey == null)
            {
                cryimol.serverKey = cryimol.GetFromKeyFile(0);
                if (cryimol.serverKey == null || cryimol.serverKey.Length == 0)
                {
                    cryimol.serverKey = cryimol.GetKeyFromAssembly(0);
                    if (cryimol.serverKey == null || cryimol.serverKey.Length == 0)
                        cryimol.serverKey = cryimol.GX_ENCRYPT_KEYVALUE;
                }
            }
            return cryimol.serverKey;
        }

        public static string GetSiteKey()
        {
            if (cryimol.siteKey == null)
            {
                cryimol.siteKey = cryimol.GetFromKeyFile(1);
                if (cryimol.siteKey == null || cryimol.siteKey.Length == 0)
                {
                    cryimol.siteKey = cryimol.GetKeyFromAssembly(1);
                    if (cryimol.siteKey == null || cryimol.siteKey.Length == 0)
                        cryimol.siteKey = cryimol.GetServerKey();
                }
            }
            return cryimol.siteKey;
        }

        private static string GetFromKeyFile(int lineNo)
        {
            string path = Path.Combine(cryimol.CurrentDir, "application.key");
            if (!File.Exists(path))
                return (string)null;
            using (FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                using (StreamReader streamReader = new StreamReader((Stream)fileStream))
                {
                    try
                    {
                        for (int index = 0; index < lineNo; ++index)
                            streamReader.ReadLine();
                        return streamReader.ReadLine();
                    }
                    catch
                    {
                        return (string)null;
                    }
                }
            }
        }

        private static string GetKeyFromAssembly(int keyType)
        {
            string name1 = "KeyResolver";
            string name2 = "GetKey";
            string keyFromAssembly = (string)null;
            try
            {
                string path = Path.Combine(cryimol.CurrentDir, name1 + ".dll");
                if (File.Exists(path))
                {
                    Type type = Assembly.LoadFile(path).GetType(name1);
                    if (type != (Type)null)
                    {
                        object obj = type.GetConstructor(Type.EmptyTypes).Invoke((object[])null);
                        MethodInfo method = type.GetMethod(name2);
                        object[] parameters = new object[2]
                        {
              (object) keyType,
              null
                        };
                        method.Invoke(obj, parameters);
                        keyFromAssembly = (string)parameters[1];
                    }
                }
            }
            catch (Exception ex)
            {
                return (string)null;
            }
            return keyFromAssembly;
        }

        public static string calcChecksum(string value, int start, int end, int length)
        {
            int intval = 0;
            for (int index = start; index < end; ++index)
                intval += (int)value[index];
            return cryimol.inttohex(intval).ToUpper().PadLeft(length, '0');
        }

        private static string inttohex(int intval) => intval.ToString("X");

        public static string CheckSum(string value, int length)
        {
            return cryimol.calcChecksum(value, 0, value.Length, length);
        }

        public static string addchecksum(string value, int length)
        {
            return value + cryimol.calcChecksum(value, 0, value.Length, length);
        }

        public static byte[] encrypt(byte[] input, object key)
        {
            int num1 = 0;
            if (input.Length % 16 != 0)
                num1 = 16 - input.Length % 16;
            byte[] numArray = new byte[input.Length + num1];
            byte[] destinationArray = new byte[numArray.Length];
            Array.Copy((Array)input, 0, (Array)numArray, 0, input.Length);
            for (int index = 0; index < num1; ++index)
                numArray[input.Length + index] = (byte)32;
            int num2 = numArray.Length / 16;
            for (int index = 0; index < num2; ++index)
                Array.Copy((Array)Twofish_Algorithm.blockEncrypt(numArray, (uint)(index * 16), key), 0, (Array)destinationArray, index * 16, 16);
            return destinationArray;
        }

        private static string toString(byte[] ba, int offset, int length)
        {
            char[] chArray1 = new char[length * 2];
            int num1 = offset;
            int num2 = 0;
            while (num1 < offset + length)
            {
                int num3 = (int)ba[num1++];
                char[] chArray2 = chArray1;
                int index1 = num2;
                int num4 = index1 + 1;
                int num5 = (int)cryimol.HEX_DIGITS[(int)Twofish_Algorithm.ror((uint)num3, (byte)32, (byte)4) & 15];
                chArray2[index1] = (char)num5;
                char[] chArray3 = chArray1;
                int index2 = num4;
                num2 = index2 + 1;
                int num6 = (int)cryimol.HEX_DIGITS[num3 & 15];
                chArray3[index2] = (char)num6;
            }
            return new string(chArray1);
        }

        public static byte[] decrypt(byte[] input, object key)
        {
            byte[] destinationArray = new byte[input.Length];
            int num = input.Length / 16;
            for (int index = 0; index < num; ++index)
                Array.Copy((Array)Twofish_Algorithm.blockDecrypt(input, (uint)(index * 16), key), 0, (Array)destinationArray, index * 16, 16);
            return destinationArray;
        }

        internal static RandomNumberGenerator RNG
        {
            get => cryimol.rng ?? (cryimol.rng = RandomNumberGenerator.Create());
        }

        public static string GetEncryptionKey()
        {
            byte[] numArray = new byte[16];
            cryimol.RNG.GetBytes(numArray);
            return cryimol.toString(numArray, 0, 16);
        }

        public static string GetRijndaelKey()
        {
            byte[] data = new byte[16];
            cryimol.RNG.GetBytes(data);
            StringBuilder stringBuilder = new StringBuilder(32);
            for (int index = 0; index < 16; ++index)
                stringBuilder.Append(data[index].ToString("X").PadLeft(2, '0'));
            return stringBuilder.ToString();
        }

        public static string DecryptRijndael(string ivEncrypted, string key, out bool candecrypt)
        {
            AesCryptoServiceProvider cryptoServiceProvider = (AesCryptoServiceProvider)null;
            candecrypt = false;
            string hexString = ivEncrypted.Length >= cryimol.GX_AJAX_PRIVATE_IV.Length ? ivEncrypted.Substring(cryimol.GX_AJAX_PRIVATE_IV.Length) : ivEncrypted;
            try
            {
                int discarded = 0;
                byte[] bytes1 = HexEncoding.GetBytes(hexString, out discarded);
                if (bytes1.Length != 0)
                {
                    byte[] bytes2 = HexEncoding.GetBytes(key, out discarded);
                    byte[] bytes3 = HexEncoding.GetBytes(cryimol.GX_AJAX_PRIVATE_IV, out discarded);
                    cryptoServiceProvider = new AesCryptoServiceProvider();
                    cryptoServiceProvider.IV = bytes3;
                    cryptoServiceProvider.Key = bytes2;
                    cryptoServiceProvider.Padding = PaddingMode.Zeros;
                    MemoryStream memoryStream;
                    using (memoryStream = new MemoryStream(bytes1))
                    {
                        CryptoStream cryptoStream;
                        using (cryptoStream = new CryptoStream((Stream)memoryStream, cryptoServiceProvider.CreateDecryptor(), CryptoStreamMode.Write))
                            cryptoStream.Write(bytes1, 0, bytes1.Length);
                    }
                    string str = Encoding.ASCII.GetString(memoryStream.ToArray());
                    int length = str.IndexOf(char.MinValue);
                    if (length != -1)
                        str = str.Substring(0, length);
                    candecrypt = true;
                    return str;
                }
            }
            catch (Exception ex)
            {
            }
            finally
            {
                cryptoServiceProvider?.Clear();
            }
            return hexString;
        }

        public static string EncryptRijndael(string decrypted, string key)
        {
            AesCryptoServiceProvider cryptoServiceProvider = (AesCryptoServiceProvider)null;
            string str = (string)null;
            try
            {
                int discarded = 0;
                byte[] bytes1 = Encoding.ASCII.GetBytes(decrypted);
                byte[] bytes2 = HexEncoding.GetBytes(key, out discarded);
                byte[] bytes3 = HexEncoding.GetBytes(cryimol.GX_AJAX_PRIVATE_IV, out discarded);
                cryptoServiceProvider = new AesCryptoServiceProvider();
                cryptoServiceProvider.IV = bytes3;
                cryptoServiceProvider.Key = bytes2;
                cryptoServiceProvider.Padding = PaddingMode.Zeros;
                MemoryStream memoryStream;
                using (memoryStream = new MemoryStream())
                {
                    CryptoStream cryptoStream;
                    using (cryptoStream = new CryptoStream((Stream)memoryStream, cryptoServiceProvider.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytes1, 0, bytes1.Length);
                        cryptoStream.FlushFinalBlock();
                        str = HexEncoding.ToString(memoryStream.ToArray());
                        int length = str.IndexOf(char.MinValue);
                        if (length != -1)
                            str = str.Substring(0, length);
                    }
                }
                return str;
            }
            catch (Exception ex)
            {
            }
            finally
            {
                cryptoServiceProvider?.Clear();
            }
            return decrypted;
        }

        private static string CurrentDir
        {
            get
            {
                if (string.IsNullOrEmpty(cryimol.s_currentDir))
                    cryimol.s_currentDir = new FileInfo(new Uri(Assembly.GetExecutingAssembly().EscapedCodeBase).LocalPath).Directory.FullName;
                return cryimol.s_currentDir;
            }
        }
    }
}

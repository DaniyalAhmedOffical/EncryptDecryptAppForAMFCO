//using System;
//using System.Collections.Generic;
//using System.ComponentModel;
//using System.Data;
//using System.Drawing;
//using System.IO;
//using System.Linq;
//using System.Security.Cryptography;
//using System.Text;
//using System.Threading.Tasks;
//using System.Windows.Forms;
//using Org.BouncyCastle.Crypto;
//using Org.BouncyCastle.Crypto.Engines;
//using Org.BouncyCastle.Crypto.Modes;
//using Org.BouncyCastle.Crypto.Paddings;
//using Org.BouncyCastle.Crypto.Parameters;

//namespace EncryptDecryptApp
//{
//    public partial class Form1 : Form
//    {
//        string key = "urFkjNMaMjwh3ToTZ5jjk0zYTLqgsBF1UgqcoE996zo=";
//        public Form1()
//        {
//            InitializeComponent();
//        }

//        private void textBox1_TextChanged(object sender, EventArgs e)
//        {

//        }

//        private void btnEncrypt_Click(object sender, EventArgs e)
//        {
//            try
//            {
//                textBox2.Text = "";
//                string txt1 = textBox1.Text;

//                string txt2 = EncryptString(txt1, key);


//                textBox2.Text = txt2;
//            }
//            catch (Exception ex)
//            {
//                throw ex;
//            }
//        }

//        private void btnDecrypt_Click(object sender, EventArgs e)
//        {
//            try
//            {
//                textBox2.Text = "";
//                string txt1 = textBox1.Text;

//                string txt2 = DecryptString(txt1, key);


//                textBox2.Text = txt2;
//            }
//            catch (Exception ex)
//            {
//                throw ex;
//            }
//        }

//        static string EncryptString(string plainText, string key)
//        {
//            byte[] iv = new byte[16];
//            byte[] array;

//            using (Aes aes = Aes.Create())
//            {
//                aes.Key = Encoding.UTF8.GetBytes(key.Substring(0, 32));
//                aes.IV = iv;

//                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

//                using (MemoryStream ms = new MemoryStream())
//                {
//                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
//                    {
//                        using (StreamWriter sw = new StreamWriter(cs))
//                        {
//                            sw.Write(plainText);
//                        }
//                    }
//                    array = ms.ToArray();
//                }
//            }
//            return Convert.ToBase64String(array);
//        }
//        static string DecryptString(string cipherText, string key)
//        {
//            byte[] iv = new byte[16];
//            byte[] buffer = Convert.FromBase64String(cipherText);

//            using (Aes aes = Aes.Create())
//            {
//                aes.Key = Encoding.UTF8.GetBytes(key.Substring(0, 32));
//                aes.IV = iv;

//                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

//                using (MemoryStream ms = new MemoryStream(buffer))
//                {
//                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
//                    {
//                        using (StreamReader reader = new StreamReader(cs))
//                        {
//                            return reader.ReadToEnd();
//                        }
//                    }
//                }
//            }
//        }



//    }
//}
using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace EncryptDecryptApp
{
    public partial class Form1 : Form
    {
        string keyHex = "A1AF0E74BCB0BECA048443CFD0A36D6B";
        public Form1() 
        {
            InitializeComponent();
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                textBox2.Text = "";
                string txt1 = textBox1.Text;

                string txt2 = TwofishEncryption.Encrypt64(txt1, keyHex);

                textBox2.Text = txt2;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Encryption failed: " + ex.Message);
            }
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                textBox2.Text = "";
                string txt1 = textBox1.Text;

                string txt2 = TwofishEncryption.Decrypt64(txt1, keyHex);

                textBox2.Text = txt2;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Decryption failed: " + ex.Message);
            }
        }
    }

    public static class TwofishEncryption
    {
        private const int BlockSize = 16; // 128 bits

        public static byte[] Encrypt(string plainText, byte[] key, byte[] iv)
        {
            var engine = new TwofishEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];

            int length = cipher.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            return outputBytes;
        }

        public static string Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            var engine = new TwofishEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] outputBytes = new byte[cipher.GetOutputSize(cipherText.Length)];

            int length = cipher.ProcessBytes(cipherText, 0, cipherText.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            return Encoding.UTF8.GetString(outputBytes).TrimEnd('\0');
        }

        public static string Encrypt64(string plainText, string keyHex)
        {
            byte[] keyBytes = HexStringToByteArray(keyHex);
            byte[] iv = new byte[BlockSize]; // You may want to use a different IV
            byte[] encrypted = Encrypt(plainText, keyBytes, iv);
            return Convert.ToBase64String(encrypted);
        }

        public static string Decrypt64(string cipherText, string keyHex)
        {
            byte[] keyBytes = HexStringToByteArray(keyHex);
            byte[] iv = new byte[BlockSize]; // You may want to use a different IV
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            return Decrypt(cipherBytes, keyBytes, iv);
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}

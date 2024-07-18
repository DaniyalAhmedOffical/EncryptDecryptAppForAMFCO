using System;
using System.Globalization;

namespace GeneXus.Encryption
{
    internal class HexEncoding
    {
        public static int GetByteCount(string hexString)
        {
            int num = 0;
            for (int index = 0; index < hexString.Length; ++index)
            {
                if (HexEncoding.IsHexDigit(hexString[index]))
                    ++num;
            }
            if (num % 2 != 0)
                --num;
            return num / 2;
        }

        public static byte[] GetBytes(string hexString, out int discarded)
        {
            discarded = 0;
            string str = "";
            for (int index = 0; index < hexString.Length; ++index)
            {
                char c = hexString[index];
                if (HexEncoding.IsHexDigit(c))
                    str += c.ToString();
                else
                    ++discarded;
            }
            if (str.Length % 2 != 0)
            {
                ++discarded;
                str = str.Substring(0, str.Length - 1);
            }
            byte[] bytes = new byte[str.Length / 2];
            int index1 = 0;
            for (int index2 = 0; index2 < bytes.Length; ++index2)
            {
                string hex = new string(new char[2]
                {
          str[index1],
          str[index1 + 1]
                });
                bytes[index2] = HexEncoding.HexToByte(hex);
                index1 += 2;
            }
            return bytes;
        }

        public static string ToString(byte[] bytes)
        {
            string str = "";
            for (int index = 0; index < bytes.Length; ++index)
                str += bytes[index].ToString("X2");
            return str;
        }

        public static bool InHexFormat(string hexString)
        {
            bool flag = true;
            foreach (char c in hexString)
            {
                if (!HexEncoding.IsHexDigit(c))
                {
                    flag = false;
                    break;
                }
            }
            return flag;
        }

        public static bool IsHexDigit(char c)
        {
            int int32_1 = Convert.ToInt32('A');
            int int32_2 = Convert.ToInt32('0');
            c = char.ToUpper(c);
            int int32_3 = Convert.ToInt32(c);
            return int32_3 >= int32_1 && int32_3 < int32_1 + 6 || int32_3 >= int32_2 && int32_3 < int32_2 + 10;
        }

        private static byte HexToByte(string hex)
        {
            return hex.Length <= 2 && hex.Length > 0 ? byte.Parse(hex, NumberStyles.HexNumber) : throw new ArgumentException("hex must be 1 or 2 characters in length");
        }
    }
}

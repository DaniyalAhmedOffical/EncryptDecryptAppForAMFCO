﻿
namespace GeneXus.Encryption
{
    internal class Base64Decoder
    {
        private char[] source;
        private int length;
        private int length2;
        private int length3;
        private int blockCount;
        private int paddingCount;

        public Base64Decoder(char[] input)
        {
            int num = 0;
            this.source = input;
            this.length = input.Length;
            for (int index = 0; index < 2; ++index)
            {
                if (this.length - index - 1 >= 0 && input[this.length - index - 1] == '=')
                    ++num;
            }
            this.paddingCount = num;
            this.blockCount = this.length / 4;
            this.length2 = this.blockCount * 3;
        }

        public byte[] GetDecoded()
        {
            byte[] numArray1 = new byte[this.length];
            byte[] numArray2 = new byte[this.length2];
            for (int index = 0; index < this.length; ++index)
                numArray1[index] = this.char2sixbit(this.source[index]);
            for (int index = 0; index < this.blockCount; ++index)
            {
                byte num1 = numArray1[index * 4];
                byte num2 = numArray1[index * 4 + 1];
                byte num3 = numArray1[index * 4 + 2];
                int num4 = (int)numArray1[index * 4 + 3];
                byte num5 = (byte)((uint)num1 << 2);
                byte num6 = (byte)((uint)(byte)(((int)num2 & 48) >> 4) + (uint)num5);
                byte num7 = (byte)(((int)num2 & 15) << 4);
                byte num8 = (byte)((uint)(byte)(((int)num3 & 60) >> 2) + (uint)num7);
                byte num9 = (byte)(((int)num3 & 3) << 6);
                byte num10 = (byte)((uint)(byte)num4 + (uint)num9);
                numArray2[index * 3] = num6;
                numArray2[index * 3 + 1] = num8;
                numArray2[index * 3 + 2] = num10;
            }
            this.length3 = this.length2 - this.paddingCount;
            byte[] decoded = new byte[this.length3];
            for (int index = 0; index < this.length3; ++index)
                decoded[index] = numArray2[index];
            return decoded;
        }

        private byte char2sixbit(char c)
        {
            char[] chArray = new char[64]
            {
        'A',
        'B',
        'C',
        'D',
        'E',
        'F',
        'G',
        'H',
        'I',
        'J',
        'K',
        'L',
        'M',
        'N',
        'O',
        'P',
        'Q',
        'R',
        'S',
        'T',
        'U',
        'V',
        'W',
        'X',
        'Y',
        'Z',
        'a',
        'b',
        'c',
        'd',
        'e',
        'f',
        'g',
        'h',
        'i',
        'j',
        'k',
        'l',
        'm',
        'n',
        'o',
        'p',
        'q',
        'r',
        's',
        't',
        'u',
        'v',
        'w',
        'x',
        'y',
        'z',
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
        '+',
        '/'
            };
            if (c == '=')
                return 0;
            for (int index = 0; index < 64; ++index)
            {
                if ((int)chArray[index] == (int)c)
                    return (byte)index;
            }
            return 0;
        }
    }
}

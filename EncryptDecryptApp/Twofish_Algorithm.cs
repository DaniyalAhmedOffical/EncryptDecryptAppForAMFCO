using System;
using System.IO;

namespace GeneXus.Encryption
{
    internal class Twofish_Algorithm
    {
        private static string NAME = nameof(Twofish_Algorithm);
        private static bool IN = true;
        private const bool OUT = false;
        private static bool DEBUG = false;
        private static int debuglevel = 0;
        private static bool TRACE = false;
        private static uint BLOCK_SIZE = 16;
        private static uint ROUNDS = 16;
        private const uint INPUT_WHITEN = 0;
        private static uint OUTPUT_WHITEN = Twofish_Algorithm.BLOCK_SIZE / 4U;
        private static uint ROUND_SUBKEYS = Twofish_Algorithm.OUTPUT_WHITEN + Twofish_Algorithm.BLOCK_SIZE / 4U;
        private static uint SK_STEP = 33686018;
        private static uint SK_BUMP = 16843009;
        private static uint SK_ROTL = 9;
        private static byte[][] P = new byte[2][]
        {
      new byte[256]
      {
        (byte) 169,
        (byte) 103,
        (byte) 179,
        (byte) 232,
        (byte) 4,
        (byte) 253,
        (byte) 163,
        (byte) 118,
        (byte) 154,
        (byte) 146,
        (byte) 128,
        (byte) 120,
        (byte) 228,
        (byte) 221,
        (byte) 209,
        (byte) 56,
        (byte) 13,
        (byte) 198,
        (byte) 53,
        (byte) 152,
        (byte) 24,
        (byte) 247,
        (byte) 236,
        (byte) 108,
        (byte) 67,
        (byte) 117,
        (byte) 55,
        (byte) 38,
        (byte) 250,
        (byte) 19,
        (byte) 148,
        (byte) 72,
        (byte) 242,
        (byte) 208,
        (byte) 139,
        (byte) 48,
        (byte) 132,
        (byte) 84,
        (byte) 223,
        (byte) 35,
        (byte) 25,
        (byte) 91,
        (byte) 61,
        (byte) 89,
        (byte) 243,
        (byte) 174,
        (byte) 162,
        (byte) 130,
        (byte) 99,
        (byte) 1,
        (byte) 131,
        (byte) 46,
        (byte) 217,
        (byte) 81,
        (byte) 155,
        (byte) 124,
        (byte) 166,
        (byte) 235,
        (byte) 165,
        (byte) 190,
        (byte) 22,
        (byte) 12,
        (byte) 227,
        (byte) 97,
        (byte) 192,
        (byte) 140,
        (byte) 58,
        (byte) 245,
        (byte) 115,
        (byte) 44,
        (byte) 37,
        (byte) 11,
        (byte) 187,
        (byte) 78,
        (byte) 137,
        (byte) 107,
        (byte) 83,
        (byte) 106,
        (byte) 180,
        (byte) 241,
        (byte) 225,
        (byte) 230,
        (byte) 189,
        (byte) 69,
        (byte) 226,
        (byte) 244,
        (byte) 182,
        (byte) 102,
        (byte) 204,
        (byte) 149,
        (byte) 3,
        (byte) 86,
        (byte) 212,
        (byte) 28,
        (byte) 30,
        (byte) 215,
        (byte) 251,
        (byte) 195,
        (byte) 142,
        (byte) 181,
        (byte) 233,
        (byte) 207,
        (byte) 191,
        (byte) 186,
        (byte) 234,
        (byte) 119,
        (byte) 57,
        (byte) 175,
        (byte) 51,
        (byte) 201,
        (byte) 98,
        (byte) 113,
        (byte) 129,
        (byte) 121,
        (byte) 9,
        (byte) 173,
        (byte) 36,
        (byte) 205,
        (byte) 249,
        (byte) 216,
        (byte) 229,
        (byte) 197,
        (byte) 185,
        (byte) 77,
        (byte) 68,
        (byte) 8,
        (byte) 134,
        (byte) 231,
        (byte) 161,
        (byte) 29,
        (byte) 170,
        (byte) 237,
        (byte) 6,
        (byte) 112,
        (byte) 178,
        (byte) 210,
        (byte) 65,
        (byte) 123,
        (byte) 160,
        (byte) 17,
        (byte) 49,
        (byte) 194,
        (byte) 39,
        (byte) 144,
        (byte) 32,
        (byte) 246,
        (byte) 96,
        byte.MaxValue,
        (byte) 150,
        (byte) 92,
        (byte) 177,
        (byte) 171,
        (byte) 158,
        (byte) 156,
        (byte) 82,
        (byte) 27,
        (byte) 95,
        (byte) 147,
        (byte) 10,
        (byte) 239,
        (byte) 145,
        (byte) 133,
        (byte) 73,
        (byte) 238,
        (byte) 45,
        (byte) 79,
        (byte) 143,
        (byte) 59,
        (byte) 71,
        (byte) 135,
        (byte) 109,
        (byte) 70,
        (byte) 214,
        (byte) 62,
        (byte) 105,
        (byte) 100,
        (byte) 42,
        (byte) 206,
        (byte) 203,
        (byte) 47,
        (byte) 252,
        (byte) 151,
        (byte) 5,
        (byte) 122,
        (byte) 172,
        (byte) 127,
        (byte) 213,
        (byte) 26,
        (byte) 75,
        (byte) 14,
        (byte) 167,
        (byte) 90,
        (byte) 40,
        (byte) 20,
        (byte) 63,
        (byte) 41,
        (byte) 136,
        (byte) 60,
        (byte) 76,
        (byte) 2,
        (byte) 184,
        (byte) 218,
        (byte) 176,
        (byte) 23,
        (byte) 85,
        (byte) 31,
        (byte) 138,
        (byte) 125,
        (byte) 87,
        (byte) 199,
        (byte) 141,
        (byte) 116,
        (byte) 183,
        (byte) 196,
        (byte) 159,
        (byte) 114,
        (byte) 126,
        (byte) 21,
        (byte) 34,
        (byte) 18,
        (byte) 88,
        (byte) 7,
        (byte) 153,
        (byte) 52,
        (byte) 110,
        (byte) 80,
        (byte) 222,
        (byte) 104,
        (byte) 101,
        (byte) 188,
        (byte) 219,
        (byte) 248,
        (byte) 200,
        (byte) 168,
        (byte) 43,
        (byte) 64,
        (byte) 220,
        (byte) 254,
        (byte) 50,
        (byte) 164,
        (byte) 202,
        (byte) 16,
        (byte) 33,
        (byte) 240,
        (byte) 211,
        (byte) 93,
        (byte) 15,
        (byte) 0,
        (byte) 111,
        (byte) 157,
        (byte) 54,
        (byte) 66,
        (byte) 74,
        (byte) 94,
        (byte) 193,
        (byte) 224
      },
      new byte[256]
      {
        (byte) 117,
        (byte) 243,
        (byte) 198,
        (byte) 244,
        (byte) 219,
        (byte) 123,
        (byte) 251,
        (byte) 200,
        (byte) 74,
        (byte) 211,
        (byte) 230,
        (byte) 107,
        (byte) 69,
        (byte) 125,
        (byte) 232,
        (byte) 75,
        (byte) 214,
        (byte) 50,
        (byte) 216,
        (byte) 253,
        (byte) 55,
        (byte) 113,
        (byte) 241,
        (byte) 225,
        (byte) 48,
        (byte) 15,
        (byte) 248,
        (byte) 27,
        (byte) 135,
        (byte) 250,
        (byte) 6,
        (byte) 63,
        (byte) 94,
        (byte) 186,
        (byte) 174,
        (byte) 91,
        (byte) 138,
        (byte) 0,
        (byte) 188,
        (byte) 157,
        (byte) 109,
        (byte) 193,
        (byte) 177,
        (byte) 14,
        (byte) 128,
        (byte) 93,
        (byte) 210,
        (byte) 213,
        (byte) 160,
        (byte) 132,
        (byte) 7,
        (byte) 20,
        (byte) 181,
        (byte) 144,
        (byte) 44,
        (byte) 163,
        (byte) 178,
        (byte) 115,
        (byte) 76,
        (byte) 84,
        (byte) 146,
        (byte) 116,
        (byte) 54,
        (byte) 81,
        (byte) 56,
        (byte) 176,
        (byte) 189,
        (byte) 90,
        (byte) 252,
        (byte) 96,
        (byte) 98,
        (byte) 150,
        (byte) 108,
        (byte) 66,
        (byte) 247,
        (byte) 16,
        (byte) 124,
        (byte) 40,
        (byte) 39,
        (byte) 140,
        (byte) 19,
        (byte) 149,
        (byte) 156,
        (byte) 199,
        (byte) 36,
        (byte) 70,
        (byte) 59,
        (byte) 112,
        (byte) 202,
        (byte) 227,
        (byte) 133,
        (byte) 203,
        (byte) 17,
        (byte) 208,
        (byte) 147,
        (byte) 184,
        (byte) 166,
        (byte) 131,
        (byte) 32,
        byte.MaxValue,
        (byte) 159,
        (byte) 119,
        (byte) 195,
        (byte) 204,
        (byte) 3,
        (byte) 111,
        (byte) 8,
        (byte) 191,
        (byte) 64,
        (byte) 231,
        (byte) 43,
        (byte) 226,
        (byte) 121,
        (byte) 12,
        (byte) 170,
        (byte) 130,
        (byte) 65,
        (byte) 58,
        (byte) 234,
        (byte) 185,
        (byte) 228,
        (byte) 154,
        (byte) 164,
        (byte) 151,
        (byte) 126,
        (byte) 218,
        (byte) 122,
        (byte) 23,
        (byte) 102,
        (byte) 148,
        (byte) 161,
        (byte) 29,
        (byte) 61,
        (byte) 240,
        (byte) 222,
        (byte) 179,
        (byte) 11,
        (byte) 114,
        (byte) 167,
        (byte) 28,
        (byte) 239,
        (byte) 209,
        (byte) 83,
        (byte) 62,
        (byte) 143,
        (byte) 51,
        (byte) 38,
        (byte) 95,
        (byte) 236,
        (byte) 118,
        (byte) 42,
        (byte) 73,
        (byte) 129,
        (byte) 136,
        (byte) 238,
        (byte) 33,
        (byte) 196,
        (byte) 26,
        (byte) 235,
        (byte) 217,
        (byte) 197,
        (byte) 57,
        (byte) 153,
        (byte) 205,
        (byte) 173,
        (byte) 49,
        (byte) 139,
        (byte) 1,
        (byte) 24,
        (byte) 35,
        (byte) 221,
        (byte) 31,
        (byte) 78,
        (byte) 45,
        (byte) 249,
        (byte) 72,
        (byte) 79,
        (byte) 242,
        (byte) 101,
        (byte) 142,
        (byte) 120,
        (byte) 92,
        (byte) 88,
        (byte) 25,
        (byte) 141,
        (byte) 229,
        (byte) 152,
        (byte) 87,
        (byte) 103,
        (byte) 127,
        (byte) 5,
        (byte) 100,
        (byte) 175,
        (byte) 99,
        (byte) 182,
        (byte) 254,
        (byte) 245,
        (byte) 183,
        (byte) 60,
        (byte) 165,
        (byte) 206,
        (byte) 233,
        (byte) 104,
        (byte) 68,
        (byte) 224,
        (byte) 77,
        (byte) 67,
        (byte) 105,
        (byte) 41,
        (byte) 46,
        (byte) 172,
        (byte) 21,
        (byte) 89,
        (byte) 168,
        (byte) 10,
        (byte) 158,
        (byte) 110,
        (byte) 71,
        (byte) 223,
        (byte) 52,
        (byte) 53,
        (byte) 106,
        (byte) 207,
        (byte) 220,
        (byte) 34,
        (byte) 201,
        (byte) 192,
        (byte) 155,
        (byte) 137,
        (byte) 212,
        (byte) 237,
        (byte) 171,
        (byte) 18,
        (byte) 162,
        (byte) 13,
        (byte) 82,
        (byte) 187,
        (byte) 2,
        (byte) 47,
        (byte) 169,
        (byte) 215,
        (byte) 97,
        (byte) 30,
        (byte) 180,
        (byte) 80,
        (byte) 4,
        (byte) 246,
        (byte) 194,
        (byte) 22,
        (byte) 37,
        (byte) 134,
        (byte) 86,
        (byte) 85,
        (byte) 9,
        (byte) 190,
        (byte) 145
      }
        };
        private const uint P_00 = 1;
        private const uint P_01 = 0;
        private const uint P_02 = 0;
        private const uint P_03 = 1;
        private const uint P_04 = 1;
        private const uint P_10 = 0;
        private const uint P_11 = 0;
        private const uint P_12 = 1;
        private const uint P_13 = 1;
        private const uint P_14 = 0;
        private const uint P_20 = 1;
        private const uint P_21 = 1;
        private const uint P_22 = 0;
        private const uint P_23 = 0;
        private const uint P_24 = 0;
        private const uint P_30 = 0;
        private const uint P_31 = 1;
        private const uint P_32 = 1;
        private const uint P_33 = 0;
        private const uint P_34 = 1;
        private static uint GF256_FDBK_2 = 180;
        private static uint GF256_FDBK_4 = 90;
        private static uint[][] MDS = Twofish_Algorithm.InitializeMds();
        private static uint RS_GF_FDBK = 333;
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



        private static void trace(bool IN, string s)
        {
            if (!Twofish_Algorithm.TRACE)
                return;

        }

        private static uint[][] InitializeMds()
        {
            uint[][] numArray1 = new uint[4][]
            {
        new uint[256],
        new uint[256],
        new uint[256],
        new uint[256]
            };
            long fileTime = DateTime.Now.ToFileTime();
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
            {
                Console.WriteLine("Algorithm Name: " + "Ahamd");
                Console.WriteLine("Electronic Codebook (ECB) Mode");
                Console.WriteLine();
            }
            uint[] numArray2 = new uint[2];
            uint[] numArray3 = new uint[2];
            uint[] numArray4 = new uint[2];
            for (uint index = 0; index < 256U; ++index)
            {
                uint x1 = (uint)Twofish_Algorithm.P[0][(int)index] & (uint)byte.MaxValue;
                numArray2[0] = x1;
                numArray3[0] = Twofish_Algorithm.Mx_X(x1) & (uint)byte.MaxValue;
                numArray4[0] = Twofish_Algorithm.Mx_Y(x1) & (uint)byte.MaxValue;
                uint x2 = (uint)Twofish_Algorithm.P[1][(int)index] & (uint)byte.MaxValue;
                numArray2[1] = x2;
                numArray3[1] = Twofish_Algorithm.Mx_X(x2) & (uint)byte.MaxValue;
                numArray4[1] = Twofish_Algorithm.Mx_Y(x2) & (uint)byte.MaxValue;
                numArray1[0][(int)index] = (uint)((int)numArray2[1] | (int)numArray3[1] << 8 | (int)numArray4[1] << 16 | (int)numArray4[1] << 24);
                numArray1[1][(int)index] = (uint)((int)numArray4[0] | (int)numArray4[0] << 8 | (int)numArray3[0] << 16 | (int)numArray2[0] << 24);
                numArray1[2][(int)index] = (uint)((int)numArray3[1] | (int)numArray4[1] << 8 | (int)numArray2[1] << 16 | (int)numArray4[1] << 24);
                numArray1[3][(int)index] = (uint)((int)numArray3[0] | (int)numArray2[0] << 8 | (int)numArray4[0] << 16 | (int)numArray3[0] << 24);
            }
            long num = DateTime.Now.ToFileTime() - fileTime;
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 8)
            {
                Console.WriteLine("==========");
                Console.WriteLine();
                Console.WriteLine("Static Data");
                Console.WriteLine();
                Console.WriteLine("MDS[0][]:");
                for (uint index1 = 0; index1 < 64U; ++index1)
                {
                    for (uint index2 = 0; index2 < 4U; ++index2)
                        Console.Write("0x" + Twofish_Algorithm.intToString(Twofish_Algorithm.MDS[0][(int)index1 * 4 + (int)index2]) + ", ");
                    Console.WriteLine();
                }
                Console.WriteLine();
                Console.WriteLine("MDS[1][]:");
                for (uint index3 = 0; index3 < 64U; ++index3)
                {
                    for (uint index4 = 0; index4 < 4U; ++index4)
                        Console.Write("0x" + Twofish_Algorithm.intToString(Twofish_Algorithm.MDS[1][(int)index3 * 4 + (int)index4]) + ", ");
                    Console.WriteLine();
                }
                Console.WriteLine();
                Console.WriteLine("MDS[2][]:");
                for (uint index5 = 0; index5 < 64U; ++index5)
                {
                    for (uint index6 = 0; index6 < 4U; ++index6)
                        Console.Write("0x" + Twofish_Algorithm.intToString(Twofish_Algorithm.MDS[2][(int)index5 * 4 + (int)index6]) + ", ");
                    Console.WriteLine();
                }
                Console.WriteLine();
                Console.WriteLine("MDS[3][]:");
                for (uint index7 = 0; index7 < 64U; ++index7)
                {
                    for (uint index8 = 0; index8 < 4U; ++index8)
                        Console.Write("0x" + Twofish_Algorithm.intToString(Twofish_Algorithm.MDS[3][(int)index7 * 4 + (int)index8]) + ", ");
                    Console.WriteLine();
                }
                Console.WriteLine();
                Console.WriteLine("Total initialization time: " + num.ToString() + " ms.");
                Console.WriteLine();
            }
            return numArray1;
        }

        private static uint LFSR1(uint x)
        {
            return x >> 1 ^ (((int)x & 1) != 0 ? Twofish_Algorithm.GF256_FDBK_2 : 0U);
        }

        private static uint LFSR2(uint x)
        {
            return (uint)((int)(x >> 2) ^ (((int)x & 2) != 0 ? (int)Twofish_Algorithm.GF256_FDBK_2 : 0) ^ (((int)x & 1) != 0 ? (int)Twofish_Algorithm.GF256_FDBK_4 : 0));
        }

        private static uint Mx_X(uint x) => x ^ Twofish_Algorithm.LFSR2(x);

        private static uint Mx_Y(uint x) => x ^ Twofish_Algorithm.LFSR1(x) ^ Twofish_Algorithm.LFSR2(x);

        public static uint ror(uint Value, byte size, byte Count)
        {
            return (uint)(((int)(Value >> (int)Count) | (int)Value << (int)size - (int)Count) & -1);
        }

        public static object makeKey(byte[] k)
        {
            if (Twofish_Algorithm.DEBUG)
                Twofish_Algorithm.trace(Twofish_Algorithm.IN, "makeKey(" + k?.ToString() + ")");
            uint num1 = k != null ? (uint)k.Length : throw new Exception("Empty key");
            switch (num1)
            {
                case 8:
                case 16:
                case 24:
                case 32:
                    if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 7)
                    {
                        Console.WriteLine("Intermediate Session Key Values");
                        Console.WriteLine();
                        Console.WriteLine("Raw=" + Twofish_Algorithm.toString(k));
                        Console.WriteLine();
                    }
                    uint k64Cnt = num1 / 8U;
                    uint length = Twofish_Algorithm.ROUND_SUBKEYS + 2U * Twofish_Algorithm.ROUNDS;
                    uint[] k32_1 = new uint[4];
                    uint[] k32_2 = new uint[4];
                    uint[] numArray1 = new uint[4];
                    uint num2 = 0;
                    uint index1 = 0;
                    uint index2 = k64Cnt - 1U;
                    while (index1 < 4U && num2 < num1)
                    {
                        uint[] numArray2 = k32_1;
                        int index3 = (int)index1;
                        byte[] numArray3 = k;
                        int index4 = (int)num2;
                        uint num3 = (uint)(index4 + 1);
                        int num4 = (int)numArray3[index4] & (int)byte.MaxValue;
                        byte[] numArray4 = k;
                        int index5 = (int)num3;
                        uint num5 = (uint)(index5 + 1);
                        int num6 = ((int)numArray4[index5] & (int)byte.MaxValue) << 8;
                        int num7 = num4 | num6;
                        byte[] numArray5 = k;
                        int index6 = (int)num5;
                        uint num8 = (uint)(index6 + 1);
                        int num9 = ((int)numArray5[index6] & (int)byte.MaxValue) << 16;
                        int num10 = num7 | num9;
                        byte[] numArray6 = k;
                        int index7 = (int)num8;
                        uint num11 = (uint)(index7 + 1);
                        int num12 = ((int)numArray6[index7] & (int)byte.MaxValue) << 24;
                        int num13 = num10 | num12;
                        numArray2[index3] = (uint)num13;
                        uint[] numArray7 = k32_2;
                        int index8 = (int)index1;
                        byte[] numArray8 = k;
                        int index9 = (int)num11;
                        uint num14 = (uint)(index9 + 1);
                        int num15 = (int)numArray8[index9] & (int)byte.MaxValue;
                        byte[] numArray9 = k;
                        int index10 = (int)num14;
                        uint num16 = (uint)(index10 + 1);
                        int num17 = ((int)numArray9[index10] & (int)byte.MaxValue) << 8;
                        int num18 = num15 | num17;
                        byte[] numArray10 = k;
                        int index11 = (int)num16;
                        uint num19 = (uint)(index11 + 1);
                        int num20 = ((int)numArray10[index11] & (int)byte.MaxValue) << 16;
                        int num21 = num18 | num20;
                        byte[] numArray11 = k;
                        int index12 = (int)num19;
                        num2 = (uint)(index12 + 1);
                        int num22 = ((int)numArray11[index12] & (int)byte.MaxValue) << 24;
                        int num23 = num21 | num22;
                        numArray7[index8] = (uint)num23;
                        numArray1[(int)index2] = Twofish_Algorithm.RS_MDS_Encode(k32_1[(int)index1], k32_2[(int)index1]);
                        ++index1;
                        --index2;
                    }
                    uint[] numArray12 = new uint[(int)length];
                    uint x1;
                    uint num24 = x1 = 0U;
                    while (num24 < length / 2U)
                    {
                        uint num25 = Twofish_Algorithm.F32(k64Cnt, x1, k32_1);
                        uint num26 = Twofish_Algorithm.F32(k64Cnt, x1 + Twofish_Algorithm.SK_BUMP, k32_2);
                        uint num27 = num26 << 8 | Twofish_Algorithm.ror(num26, (byte)32, (byte)24);
                        uint num28 = num25 + num27;
                        numArray12[2 * (int)num24] = num28;
                        uint num29 = num28 + num27;
                        numArray12[2 * (int)num24 + 1] = num29 << (int)(byte)Twofish_Algorithm.SK_ROTL | Twofish_Algorithm.ror(num29, (byte)32, (byte)(32U - Twofish_Algorithm.SK_ROTL));
                        ++num24;
                        x1 += Twofish_Algorithm.SK_STEP;
                    }
                    uint x2 = numArray1[0];
                    uint x3 = numArray1[1];
                    uint x4 = numArray1[2];
                    uint x5 = numArray1[3];
                    uint[] numArray13 = new uint[1024];
                    for (uint index13 = 0; index13 < 256U; ++index13)
                    {
                        int num30;
                        uint index14 = (uint)(num30 = (int)index13);
                        uint index15 = (uint)num30;
                        uint index16 = (uint)num30;
                        uint index17 = (uint)num30;
                        switch (k64Cnt & 3U)
                        {
                            case 0:
                                index17 = (uint)((ulong)((int)Twofish_Algorithm.P[1][(int)index17] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b0(x5));
                                index16 = (uint)((ulong)((int)Twofish_Algorithm.P[0][(int)index16] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b1(x5));
                                index15 = (uint)((ulong)((int)Twofish_Algorithm.P[0][(int)index15] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b2(x5));
                                index14 = (uint)((ulong)((int)Twofish_Algorithm.P[1][(int)index14] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b3(x5));
                                goto case 3;
                            case 1:
                                numArray13[2 * (int)index13] = Twofish_Algorithm.MDS[0][(long)((int)Twofish_Algorithm.P[0][(int)index17] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b0(x2)];
                                numArray13[2 * (int)index13 + 1] = Twofish_Algorithm.MDS[1][(long)((int)Twofish_Algorithm.P[0][(int)index16] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b1(x2)];
                                numArray13[512 + 2 * (int)index13] = Twofish_Algorithm.MDS[2][(long)((int)Twofish_Algorithm.P[1][(int)index15] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b2(x2)];
                                numArray13[512 + 2 * (int)index13 + 1] = Twofish_Algorithm.MDS[3][(long)((int)Twofish_Algorithm.P[1][(int)index14] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b3(x2)];
                                break;
                            case 2:
                                numArray13[2 * (int)index13] = Twofish_Algorithm.MDS[0][(long)((int)Twofish_Algorithm.P[0][(long)((int)Twofish_Algorithm.P[0][(int)index17] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b0(x3)] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b0(x2)];
                                numArray13[2 * (int)index13 + 1] = Twofish_Algorithm.MDS[1][(long)((int)Twofish_Algorithm.P[0][(long)((int)Twofish_Algorithm.P[1][(int)index16] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b1(x3)] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b1(x2)];
                                numArray13[512 + 2 * (int)index13] = Twofish_Algorithm.MDS[2][(long)((int)Twofish_Algorithm.P[1][(long)((int)Twofish_Algorithm.P[0][(int)index15] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b2(x3)] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b2(x2)];
                                numArray13[512 + 2 * (int)index13 + 1] = Twofish_Algorithm.MDS[3][(long)((int)Twofish_Algorithm.P[1][(long)((int)Twofish_Algorithm.P[1][(int)index14] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b3(x3)] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b3(x2)];
                                break;
                            case 3:
                                index17 = (uint)((ulong)((int)Twofish_Algorithm.P[1][(int)index17] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b0(x4));
                                index16 = (uint)((ulong)((int)Twofish_Algorithm.P[1][(int)index16] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b1(x4));
                                index15 = (uint)Twofish_Algorithm.P[0][(int)index15] & (uint)byte.MaxValue ^ Twofish_Algorithm._b2(x4);
                                index14 = (uint)Twofish_Algorithm.P[0][(int)index14] & (uint)byte.MaxValue ^ Twofish_Algorithm._b3(x4);
                                goto case 2;
                        }
                    }
                    object obj = (object)new object[2]
                    {
            (object) numArray13,
            (object) numArray12
                    };
                    if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 7)
                    {
                        Console.WriteLine("S-box[]:");
                        for (uint index18 = 0; index18 < 64U; ++index18)
                        {
                            for (uint index19 = 0; index19 < 4U; ++index19)
                                Console.Write("0x" + Twofish_Algorithm.intToString(numArray13[(int)index18 * 4 + (int)index19]) + ", ");
                            Console.WriteLine();
                        }
                        Console.WriteLine();
                        for (uint index20 = 0; index20 < 64U; ++index20)
                        {
                            for (uint index21 = 0; index21 < 4U; ++index21)
                                Console.Write("0x" + Twofish_Algorithm.intToString(numArray13[256 + (int)index20 * 4 + (int)index21]) + ", ");
                            Console.WriteLine();
                        }
                        Console.WriteLine();
                        for (uint index22 = 0; index22 < 64U; ++index22)
                        {
                            for (uint index23 = 0; index23 < 4U; ++index23)
                                Console.Write("0x" + Twofish_Algorithm.intToString(numArray13[512 + (int)index22 * 4 + (int)index23]) + ", ");
                            Console.WriteLine();
                        }
                        Console.WriteLine();
                        for (uint index24 = 0; index24 < 64U; ++index24)
                        {
                            for (uint index25 = 0; index25 < 4U; ++index25)
                                Console.Write("0x" + Twofish_Algorithm.intToString(numArray13[768 + (int)index24 * 4 + (int)index25]) + ", ");
                            Console.WriteLine();
                        }
                        Console.WriteLine();
                        Console.WriteLine("User (odd, even) keys  --> S-Box keys:");
                        for (uint index26 = 0; index26 < k64Cnt; ++index26)
                            Console.WriteLine("0x" + Twofish_Algorithm.intToString(k32_2[(int)index26]) + "  0x" + Twofish_Algorithm.intToString(k32_1[(int)index26]) + " --> 0x" + Twofish_Algorithm.intToString(numArray1[(int)k64Cnt - 1 - (int)index26]));
                        Console.WriteLine();
                        Console.WriteLine("Round keys:");
                        for (uint index27 = 0; index27 < Twofish_Algorithm.ROUND_SUBKEYS + 2U * Twofish_Algorithm.ROUNDS; index27 += 2U)
                            Console.WriteLine("0x" + Twofish_Algorithm.intToString(numArray12[(int)index27]) + "  0x" + Twofish_Algorithm.intToString(numArray12[(int)index27 + 1]));
                        Console.WriteLine();
                    }
                    if (Twofish_Algorithm.DEBUG)
                        Twofish_Algorithm.trace(false, "makeKey()");
                    return obj;
                default:
                    throw new Exception("Incorrect key length");
            }
        }

        public static byte[] blockEncrypt(byte[] _in, uint inOffset, object sessionKey)
        {
            if (Twofish_Algorithm.DEBUG)
                Twofish_Algorithm.trace((Twofish_Algorithm.IN ? 1 : 0) != 0, "blockEncrypt(" + _in?.ToString() + ", " + inOffset.ToString() + ", " + sessionKey?.ToString() + ")");
            object[] objArray = (object[])sessionKey;
            uint[] sBox = (uint[])objArray[0];
            uint[] numArray1 = (uint[])objArray[1];
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                Console.WriteLine("PT=" + Twofish_Algorithm.toString(_in, inOffset, Twofish_Algorithm.BLOCK_SIZE));
            uint num1 = (uint)((int)_in[(int)inOffset++] & (int)byte.MaxValue | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 8 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 16 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 24);
            uint num2 = (uint)((int)_in[(int)inOffset++] & (int)byte.MaxValue | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 8 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 16 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 24);
            uint num3 = (uint)((int)_in[(int)inOffset++] & (int)byte.MaxValue | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 8 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 16 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 24);
            uint num4 = (uint)((int)_in[(int)inOffset++] & (int)byte.MaxValue | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 8 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 16 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 24);
            uint num5 = num1 ^ numArray1[0];
            uint num6 = num2 ^ numArray1[1];
            uint num7 = num3 ^ numArray1[2];
            uint num8 = num4 ^ numArray1[3];
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                Console.WriteLine("PTw=" + Twofish_Algorithm.intToString(num5) + Twofish_Algorithm.intToString(num6) + Twofish_Algorithm.intToString(num7) + Twofish_Algorithm.intToString(num8));
            uint num9 = Twofish_Algorithm.ROUND_SUBKEYS;
            for (uint index1 = 0; index1 < Twofish_Algorithm.ROUNDS; index1 += 2U)
            {
                uint num10 = Twofish_Algorithm.Fe32(sBox, num5, 0U);
                uint num11 = Twofish_Algorithm.Fe32(sBox, num6, 3U);
                int num12 = (int)num7;
                int num13 = (int)num10 + (int)num11;
                uint[] numArray2 = numArray1;
                int index2 = (int)num9;
                uint num14 = (uint)(index2 + 1);
                int num15 = (int)numArray2[index2];
                int num16 = num13 + num15;
                uint num17 = (uint)(num12 ^ num16);
                num7 = Twofish_Algorithm.ror(num17, (byte)32, (byte)1) | num17 << 31;
                int num18 = (int)(num8 << 1 | Twofish_Algorithm.ror(num8, (byte)32, (byte)31));
                int num19 = (int)num10 + 2 * (int)num11;
                uint[] numArray3 = numArray1;
                int index3 = (int)num14;
                uint num20 = (uint)(index3 + 1);
                int num21 = (int)numArray3[index3];
                int num22 = num19 + num21;
                num8 = (uint)(num18 ^ num22);
                if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                    Console.WriteLine("CT" + index1.ToString() + "=" + Twofish_Algorithm.intToString(num5) + Twofish_Algorithm.intToString(num6) + Twofish_Algorithm.intToString(num7) + Twofish_Algorithm.intToString(num8));
                uint num23 = Twofish_Algorithm.Fe32(sBox, num7, 0U);
                uint num24 = Twofish_Algorithm.Fe32(sBox, num8, 3U);
                int num25 = (int)num5;
                int num26 = (int)num23 + (int)num24;
                uint[] numArray4 = numArray1;
                int index4 = (int)num20;
                uint num27 = (uint)(index4 + 1);
                int num28 = (int)numArray4[index4];
                int num29 = num26 + num28;
                uint num30 = (uint)(num25 ^ num29);
                num5 = Twofish_Algorithm.ror(num30, (byte)32, (byte)1) | num30 << 31;
                int num31 = (int)(num6 << 1 | Twofish_Algorithm.ror(num6, (byte)32, (byte)31));
                int num32 = (int)num23 + 2 * (int)num24;
                uint[] numArray5 = numArray1;
                int index5 = (int)num27;
                num9 = (uint)(index5 + 1);
                int num33 = (int)numArray5[index5];
                int num34 = num32 + num33;
                num6 = (uint)(num31 ^ num34);
                if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                    Console.WriteLine("CT" + (index1 + 1U).ToString() + "=" + Twofish_Algorithm.intToString(num5) + Twofish_Algorithm.intToString(num6) + Twofish_Algorithm.intToString(num7) + Twofish_Algorithm.intToString(num8));
            }
            uint n1 = num7 ^ numArray1[(int)Twofish_Algorithm.OUTPUT_WHITEN];
            uint n2 = num8 ^ numArray1[(int)Twofish_Algorithm.OUTPUT_WHITEN + 1];
            uint n3 = num5 ^ numArray1[(int)Twofish_Algorithm.OUTPUT_WHITEN + 2];
            uint n4 = num6 ^ numArray1[(int)Twofish_Algorithm.OUTPUT_WHITEN + 3];
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                Console.WriteLine("CTw=" + Twofish_Algorithm.intToString(n3) + Twofish_Algorithm.intToString(n4) + Twofish_Algorithm.intToString(n1) + Twofish_Algorithm.intToString(n2));
            byte[] ba = new byte[16]
            {
        (byte) n1,
        (byte) Twofish_Algorithm.ror(n1, (byte) 32, (byte) 8),
        (byte) Twofish_Algorithm.ror(n1, (byte) 32, (byte) 16),
        (byte) Twofish_Algorithm.ror(n1, (byte) 32, (byte) 24),
        (byte) n2,
        (byte) Twofish_Algorithm.ror(n2, (byte) 32, (byte) 8),
        (byte) Twofish_Algorithm.ror(n2, (byte) 32, (byte) 16),
        (byte) Twofish_Algorithm.ror(n2, (byte) 32, (byte) 24),
        (byte) n3,
        (byte) Twofish_Algorithm.ror(n3, (byte) 32, (byte) 8),
        (byte) Twofish_Algorithm.ror(n3, (byte) 32, (byte) 16),
        (byte) Twofish_Algorithm.ror(n3, (byte) 32, (byte) 24),
        (byte) n4,
        (byte) Twofish_Algorithm.ror(n4, (byte) 32, (byte) 8),
        (byte) Twofish_Algorithm.ror(n4, (byte) 32, (byte) 16),
        (byte) Twofish_Algorithm.ror(n4, (byte) 32, (byte) 24)
            };
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
            {
                Console.WriteLine("CT=" + Twofish_Algorithm.toString(ba));
                Console.WriteLine();
            }
            if (Twofish_Algorithm.DEBUG)
                Twofish_Algorithm.trace(false, "blockEncrypt()");
            return ba;
        }

        public static byte[] blockDecrypt(byte[] _in, uint inOffset, object sessionKey)
        {
            if (Twofish_Algorithm.DEBUG)
                Twofish_Algorithm.trace((Twofish_Algorithm.IN ? 1 : 0) != 0, "blockDecrypt(" + _in?.ToString() + ", " + inOffset.ToString() + ", " + sessionKey?.ToString() + ")");
            object[] objArray = (object[])sessionKey;
            uint[] sBox = (uint[])objArray[0];
            uint[] numArray1 = (uint[])objArray[1];
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                Console.WriteLine("CT=" + Twofish_Algorithm.toString(_in, inOffset, Twofish_Algorithm.BLOCK_SIZE));
            uint num1 = (uint)((int)_in[(int)inOffset++] & (int)byte.MaxValue | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 8 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 16 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 24);
            uint num2 = (uint)((int)_in[(int)inOffset++] & (int)byte.MaxValue | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 8 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 16 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 24);
            uint num3 = (uint)((int)_in[(int)inOffset++] & (int)byte.MaxValue | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 8 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 16 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 24);
            uint num4 = (uint)((int)_in[(int)inOffset++] & (int)byte.MaxValue | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 8 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 16 | ((int)_in[(int)inOffset++] & (int)byte.MaxValue) << 24);
            uint num5 = num1 ^ numArray1[(int)Twofish_Algorithm.OUTPUT_WHITEN];
            uint num6 = num2 ^ numArray1[(int)Twofish_Algorithm.OUTPUT_WHITEN + 1];
            uint num7 = num3 ^ numArray1[(int)Twofish_Algorithm.OUTPUT_WHITEN + 2];
            uint num8 = num4 ^ numArray1[(int)Twofish_Algorithm.OUTPUT_WHITEN + 3];
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                Console.WriteLine("CTw=" + Twofish_Algorithm.intToString(num5) + Twofish_Algorithm.intToString(num6) + Twofish_Algorithm.intToString(num7) + Twofish_Algorithm.intToString(num8));
            uint num9 = (uint)((int)Twofish_Algorithm.ROUND_SUBKEYS + 2 * (int)Twofish_Algorithm.ROUNDS - 1);
            for (uint index1 = 0; index1 < Twofish_Algorithm.ROUNDS; index1 += 2U)
            {
                uint num10 = Twofish_Algorithm.Fe32(sBox, num5, 0U);
                uint num11 = Twofish_Algorithm.Fe32(sBox, num6, 3U);
                int num12 = (int)num8;
                int num13 = (int)num10 + 2 * (int)num11;
                uint[] numArray2 = numArray1;
                int index2 = (int)num9;
                uint num14 = (uint)(index2 - 1);
                int num15 = (int)numArray2[index2];
                int num16 = num13 + num15;
                uint num17 = (uint)(num12 ^ num16);
                num8 = Twofish_Algorithm.ror(num17, (byte)32, (byte)1) | num17 << 31;
                int num18 = (int)(num7 << 1 | Twofish_Algorithm.ror(num7, (byte)32, (byte)31));
                int num19 = (int)num10 + (int)num11;
                uint[] numArray3 = numArray1;
                int index3 = (int)num14;
                uint num20 = (uint)(index3 - 1);
                int num21 = (int)numArray3[index3];
                int num22 = num19 + num21;
                num7 = (uint)(num18 ^ num22);
                if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                    Console.WriteLine("PT" + (Twofish_Algorithm.ROUNDS - index1).ToString() + "=" + Twofish_Algorithm.intToString(num5) + Twofish_Algorithm.intToString(num6) + Twofish_Algorithm.intToString(num7) + Twofish_Algorithm.intToString(num8));
                uint num23 = Twofish_Algorithm.Fe32(sBox, num7, 0U);
                uint num24 = Twofish_Algorithm.Fe32(sBox, num8, 3U);
                int num25 = (int)num6;
                int num26 = (int)num23 + 2 * (int)num24;
                uint[] numArray4 = numArray1;
                int index4 = (int)num20;
                uint num27 = (uint)(index4 - 1);
                int num28 = (int)numArray4[index4];
                int num29 = num26 + num28;
                uint num30 = (uint)(num25 ^ num29);
                num6 = Twofish_Algorithm.ror(num30, (byte)32, (byte)1) | num30 << 31;
                int num31 = (int)(num5 << 1 | Twofish_Algorithm.ror(num5, (byte)32, (byte)31));
                int num32 = (int)num23 + (int)num24;
                uint[] numArray5 = numArray1;
                int index5 = (int)num27;
                num9 = (uint)(index5 - 1);
                int num33 = (int)numArray5[index5];
                int num34 = num32 + num33;
                num5 = (uint)(num31 ^ num34);
                if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                    Console.WriteLine("PT" + ((uint)((int)Twofish_Algorithm.ROUNDS - (int)index1 - 1)).ToString() + "=" + Twofish_Algorithm.intToString(num5) + Twofish_Algorithm.intToString(num6) + Twofish_Algorithm.intToString(num7) + Twofish_Algorithm.intToString(num8));
            }
            uint n1 = num7 ^ numArray1[0];
            uint n2 = num8 ^ numArray1[1];
            uint n3 = num5 ^ numArray1[2];
            uint n4 = num6 ^ numArray1[3];
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                Console.WriteLine("PTw=" + Twofish_Algorithm.intToString(n3) + Twofish_Algorithm.intToString(n4) + Twofish_Algorithm.intToString(n1) + Twofish_Algorithm.intToString(n2));
            byte[] ba = new byte[16]
            {
        (byte) n1,
        (byte) Twofish_Algorithm.ror(n1, (byte) 32, (byte) 8),
        (byte) Twofish_Algorithm.ror(n1, (byte) 32, (byte) 16),
        (byte) Twofish_Algorithm.ror(n1, (byte) 32, (byte) 24),
        (byte) n2,
        (byte) Twofish_Algorithm.ror(n2, (byte) 32, (byte) 8),
        (byte) Twofish_Algorithm.ror(n2, (byte) 32, (byte) 16),
        (byte) Twofish_Algorithm.ror(n2, (byte) 32, (byte) 24),
        (byte) n3,
        (byte) Twofish_Algorithm.ror(n3, (byte) 32, (byte) 8),
        (byte) Twofish_Algorithm.ror(n3, (byte) 32, (byte) 16),
        (byte) Twofish_Algorithm.ror(n3, (byte) 32, (byte) 24),
        (byte) n4,
        (byte) Twofish_Algorithm.ror(n4, (byte) 32, (byte) 8),
        (byte) Twofish_Algorithm.ror(n4, (byte) 32, (byte) 16),
        (byte) Twofish_Algorithm.ror(n4, (byte) 32, (byte) 24)
            };
            if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
            {
                Console.WriteLine("PT=" + Twofish_Algorithm.toString(ba));
                Console.WriteLine();
            }
            if (Twofish_Algorithm.DEBUG)
                Twofish_Algorithm.trace(false, "blockDecrypt()");
            return ba;
        }

        public static bool self_test() => Twofish_Algorithm.self_test(Twofish_Algorithm.BLOCK_SIZE);

        private static uint _b0(uint x) => x & (uint)byte.MaxValue;

        private static uint _b1(uint x)
        {
            return Twofish_Algorithm.ror(x, (byte)32, (byte)8) & (uint)byte.MaxValue;
        }

        private static uint _b2(uint x)
        {
            return Twofish_Algorithm.ror(x, (byte)32, (byte)16) & (uint)byte.MaxValue;
        }

        private static uint _b3(uint x)
        {
            return Twofish_Algorithm.ror(x, (byte)32, (byte)24) & (uint)byte.MaxValue;
        }

        private static uint RS_MDS_Encode(uint k0, uint k1)
        {
            uint x1 = k1;
            for (uint index = 0; index < 4U; ++index)
                x1 = Twofish_Algorithm.RS_rem(x1);
            uint x2 = x1 ^ k0;
            for (uint index = 0; index < 4U; ++index)
                x2 = Twofish_Algorithm.RS_rem(x2);
            return x2;
        }

        private static uint RS_rem(uint x)
        {
            uint num1 = Twofish_Algorithm.ror(x, (byte)32, (byte)24) & (uint)byte.MaxValue;
            uint num2 = (uint)(((int)num1 << 1 ^ (((int)num1 & 128) != 0 ? (int)Twofish_Algorithm.RS_GF_FDBK : 0)) & (int)byte.MaxValue);
            uint num3 = Twofish_Algorithm.ror(num1, (byte)32, (byte)1) ^ (((int)num1 & 1) != 0 ? Twofish_Algorithm.ror(Twofish_Algorithm.RS_GF_FDBK, (byte)32, (byte)1) : 0U) ^ num2;
            return (uint)((int)x << 8 ^ (int)num3 << 24 ^ (int)num2 << 16 ^ (int)num3 << 8) ^ num1;
        }

        private static uint F32(uint k64Cnt, uint x, uint[] k32)
        {
            uint index1 = Twofish_Algorithm._b0(x);
            uint index2 = Twofish_Algorithm._b1(x);
            uint index3 = Twofish_Algorithm._b2(x);
            uint index4 = Twofish_Algorithm._b3(x);
            uint x1 = k32[0];
            uint x2 = k32[1];
            uint x3 = k32[2];
            uint x4 = k32[3];
            uint num = 0;
            switch (k64Cnt & 3U)
            {
                case 0:
                    index1 = (uint)((ulong)((int)Twofish_Algorithm.P[1][(int)index1] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b0(x4));
                    index2 = (uint)((ulong)((int)Twofish_Algorithm.P[0][(int)index2] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b1(x4));
                    index3 = (uint)((ulong)((int)Twofish_Algorithm.P[0][(int)index3] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b2(x4));
                    index4 = (uint)((ulong)((int)Twofish_Algorithm.P[1][(int)index4] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b3(x4));
                    goto case 3;
                case 1:
                    num = Twofish_Algorithm.MDS[0][(long)((int)Twofish_Algorithm.P[0][(int)index1] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b0(x1)] ^ Twofish_Algorithm.MDS[1][(long)((int)Twofish_Algorithm.P[0][(int)index2] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b1(x1)] ^ Twofish_Algorithm.MDS[2][(long)((int)Twofish_Algorithm.P[1][(int)index3] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b2(x1)] ^ Twofish_Algorithm.MDS[3][(long)((int)Twofish_Algorithm.P[1][(int)index4] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b3(x1)];
                    break;
                case 2:
                    num = Twofish_Algorithm.MDS[0][(long)((int)Twofish_Algorithm.P[0][(long)((int)Twofish_Algorithm.P[0][(int)index1] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b0(x2)] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b0(x1)] ^ Twofish_Algorithm.MDS[1][(long)((int)Twofish_Algorithm.P[0][(long)((int)Twofish_Algorithm.P[1][(int)index2] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b1(x2)] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b1(x1)] ^ Twofish_Algorithm.MDS[2][(long)((int)Twofish_Algorithm.P[1][(long)((int)Twofish_Algorithm.P[0][(int)index3] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b2(x2)] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b2(x1)] ^ Twofish_Algorithm.MDS[3][(long)((int)Twofish_Algorithm.P[1][(long)((int)Twofish_Algorithm.P[1][(int)index4] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b3(x2)] & (int)byte.MaxValue) ^ (long)Twofish_Algorithm._b3(x1)];
                    break;
                case 3:
                    index1 = (uint)((ulong)((int)Twofish_Algorithm.P[1][(int)index1] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b0(x3));
                    index2 = (uint)((ulong)((int)Twofish_Algorithm.P[1][(int)index2] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b1(x3));
                    index3 = (uint)((ulong)((int)Twofish_Algorithm.P[0][(int)index3] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b2(x3));
                    index4 = (uint)((ulong)((int)Twofish_Algorithm.P[0][(int)index4] & (int)byte.MaxValue) ^ (ulong)Twofish_Algorithm._b3(x3));
                    goto case 2;
            }
            return num;
        }

        private static uint Fe32(uint[] sBox, uint x, uint R)
        {
            return sBox[2 * (int)Twofish_Algorithm._b(x, R)] ^ sBox[2 * (int)Twofish_Algorithm._b(x, R + 1U) + 1] ^ sBox[512 + 2 * (int)Twofish_Algorithm._b(x, R + 2U)] ^ sBox[512 + 2 * (int)Twofish_Algorithm._b(x, R + 3U) + 1];
        }

        private static uint _b(uint x, uint N)
        {
            uint num = 0;
            switch (N % 4U)
            {
                case 0:
                    num = Twofish_Algorithm._b0(x);
                    break;
                case 1:
                    num = Twofish_Algorithm._b1(x);
                    break;
                case 2:
                    num = Twofish_Algorithm._b2(x);
                    break;
                case 3:
                    num = Twofish_Algorithm._b3(x);
                    break;
            }
            return num;
        }

        public static uint blockSize() => Twofish_Algorithm.BLOCK_SIZE;

        private static bool self_test(uint keysize)
        {
            if (Twofish_Algorithm.DEBUG)
                Twofish_Algorithm.trace(Twofish_Algorithm.IN, "self_test(" + keysize.ToString() + ")");
            bool flag = false;
            try
            {
                byte[] numArray1 = new byte[(int)keysize];
                byte[] numArray2 = new byte[(int)Twofish_Algorithm.BLOCK_SIZE];
                for (uint index = 0; index < keysize; ++index)
                    numArray1[(int)index] = (byte)index;
                for (uint index = 0; index < Twofish_Algorithm.BLOCK_SIZE; ++index)
                    numArray2[(int)index] = (byte)index;
                if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                {
                    Console.WriteLine("==========");
                    Console.WriteLine();
                    Console.WriteLine("KEYSIZE=" + (8U * keysize).ToString());
                    Console.WriteLine("KEY=" + Twofish_Algorithm.toString(numArray1));
                    Console.WriteLine();
                }
                object sessionKey1 = Twofish_Algorithm.makeKey(numArray1);
                if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                {
                    Console.WriteLine("Intermediate Ciphertext Values (Encryption)");
                    Console.WriteLine();
                }
                byte[] _in = Twofish_Algorithm.blockEncrypt(numArray2, 0U, sessionKey1);
                if (Twofish_Algorithm.DEBUG && Twofish_Algorithm.debuglevel > 6)
                {
                    Console.WriteLine("Intermediate Plaintext Values (Decryption)");
                    Console.WriteLine();
                }
                object sessionKey2 = sessionKey1;
                byte[] b = Twofish_Algorithm.blockDecrypt(_in, 0U, sessionKey2);
                flag = Twofish_Algorithm.areEqual(numArray2, b);
                if (!flag)
                    throw new Exception("Symmetric operation failed");
            }
            catch (Exception ex)
            {
                if (Twofish_Algorithm.DEBUG)
                {
                    if (Twofish_Algorithm.debuglevel > 0)
                    {

                    }
                }
            }

            if (Twofish_Algorithm.DEBUG)
                Twofish_Algorithm.trace(false, "self_test()");
            return flag;
        }

        private static bool areEqual(byte[] a, byte[] b)
        {
            uint length = (uint)a.Length;
            if ((long)length != (long)b.Length)
                return false;
            for (uint index = 0; index < length; ++index)
            {
                if ((int)a[(int)index] != (int)b[(int)index])
                    return false;
            }
            return true;
        }

        private static string intToString(uint n)
        {
            char[] chArray = new char[8];
            for (sbyte index = 7; index >= (sbyte)0; --index)
            {
                chArray[(int)index] = Twofish_Algorithm.HEX_DIGITS[(int)n & 15];
                n = Twofish_Algorithm.ror(n, (byte)32, (byte)4);
            }
            return new string(chArray);
        }

        private static string toString(byte[] ba)
        {
            return Twofish_Algorithm.toString(ba, 0U, (uint)ba.Length);
        }

        private static string toString(byte[] ba, uint offset, uint length)
        {
            char[] chArray1 = new char[(int)length * 2];
            uint num1 = offset;
            uint num2 = 0;
            while (num1 < offset + length)
            {
                uint num3 = (uint)ba[(int)num1++];
                char[] chArray2 = chArray1;
                int index1 = (int)num2;
                uint num4 = (uint)(index1 + 1);
                int num5 = (int)Twofish_Algorithm.HEX_DIGITS[(int)Twofish_Algorithm.ror(num3, (byte)32, (byte)4) & 15];
                chArray2[index1] = (char)num5;
                char[] chArray3 = chArray1;
                int index2 = (int)num4;
                num2 = (uint)(index2 + 1);
                int num6 = (int)Twofish_Algorithm.HEX_DIGITS[(int)num3 & 15];
                chArray3[index2] = (char)num6;
            }
            return new string(chArray1);
        }

        public static void _Main(string[] args)
        {
            Console.WriteLine("Inicio testeo");
            Twofish_Algorithm.self_test(16U);
            Twofish_Algorithm.self_test(24U);
            Twofish_Algorithm.self_test(32U);
            Console.WriteLine("Fin testeo");
        }
    }
}

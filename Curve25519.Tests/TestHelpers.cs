using System;
using System.Collections;

namespace Elliptic.Tests
{
    public static class TestHelpers
    {
        public static Random CreateSemiRandomGenerator()
        {
            DateTime now = DateTime.Now;
            return new Random(now.DayOfYear * 365 + now.Hour);
        }

        public static byte[] GetRandomBytes(Random random, int size)
        {
            byte[] result = new byte[size];
            for (int i = 0; i < size; i++)
            {
                result[i] = (byte)random.Next(256);
            }
            return result;
        }

        public static byte[] GetUniformBytes(byte value, int size)
        {
            byte[] result = new byte[size];
            for (int i = 0; i < size; i++)
            {
                result[i] = value;
            }
            return result;
        }

        public static byte[] ToggleBitInKey(byte[] buffer, Random random)
        {
            var bitToToggle = random.Next(buffer.Length*8);

            var result = new byte[buffer.Length];

            buffer.CopyTo(result, 0);
            result[bitToToggle / 8] ^= (byte)(1 << bitToToggle % 8);

            return result;
        }
    }
}

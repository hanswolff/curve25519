using NUnit.Framework;
using System.Collections.Generic;
using System.Diagnostics;

namespace Elliptic.Tests
{
    [Explicit]
    [TestFixture]
    public class Curve25519TimingTests
    {
        [Test]
        public void Curve25519_GetPublicKey()
        {
            List<long> ticks = new List<long>();
            for (int i = 0; i < 255; i++)
            {
                Stopwatch stopwatch = Stopwatch.StartNew();

                byte[] privateKey = Curve25519.ClampPrivateKey(TestHelpers.GetUniformBytes((byte)i, 32));

                for (int j = 0; j < 1000; j++)
                {
                    byte[] publicKey = Curve25519.GetPublicKey(privateKey);
                }

                ticks.Add(stopwatch.ElapsedMilliseconds);
            }

            long min = long.MaxValue;
            long max = long.MinValue;
            for (int i = 0; i < ticks.Count; i++)
            {
                if (ticks[i] < min) min = ticks[i];
                if (ticks[i] > max) max = ticks[i];
            }

            Assert.Inconclusive("Min: {0}, Max: {1}", min, max);
        }
    }
}
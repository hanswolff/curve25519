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
            var ticks = new List<long>();
            for (var i = 0; i < 255; i++)
            {
                var stopwatch = Stopwatch.StartNew();

                var privateKey = Curve25519.ClampPrivateKey(TestHelpers.GetUniformBytes((byte)i, 32));

                for (var j = 0; j < 1000; j++)
                {
                    var publicKey = Curve25519.GetPublicKey(privateKey);
                }

                ticks.Add(stopwatch.ElapsedMilliseconds);
            }

            var min = long.MaxValue;
            var max = long.MinValue;
            foreach (var t in ticks)
            {
                if (t < min) min = t;
                if (t > max) max = t;
            }

            Assert.Inconclusive("Min: {0}, Max: {1}", min, max);
        }
    }
}
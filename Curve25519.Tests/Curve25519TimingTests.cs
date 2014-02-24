using NUnit.Framework;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Elliptic.Tests
{
    [Explicit]
    [TestFixture]
    public class Curve25519TimingTests
    {
        [Test]
        public void Curve25519_GetPublicKey()
        {
            var millis = new List<long>();
            for (var i = 0; i < 255; i++)
            {
                var privateKey = Curve25519.ClampPrivateKey(TestHelpers.GetUniformBytes((byte)i, 32));
                Curve25519.GetPublicKey(privateKey);

                var stopwatch = Stopwatch.StartNew();

                for (var j = 0; j < 100; j++)
                {
                    Curve25519.GetPublicKey(privateKey);
                }

                millis.Add(stopwatch.ElapsedMilliseconds);
            }

            var text = new StringBuilder();
            foreach (var ms in millis)
                text.Append(ms + ",");
            Assert.Inconclusive(text.ToString());
        }

        [Test]
        public void Curve25519_GetSharedSecret()
        {
            var millis = new List<long>();
            for (var i = 0; i < 255; i++)
            {
                var privateKey = Curve25519.ClampPrivateKey(TestHelpers.GetUniformBytes((byte)i, 32));
                var publicKey = Curve25519.GetPublicKey(privateKey);
                Curve25519.GetSharedSecret(privateKey, publicKey);

                var stopwatch = Stopwatch.StartNew();

                for (var j = 0; j < 100; j++)
                {
                    Curve25519.GetSharedSecret(privateKey, publicKey);
                }

                millis.Add(stopwatch.ElapsedMilliseconds);
            }

            var text = new StringBuilder();
            foreach (var ms in millis)
                text.Append(ms + ",");
            Assert.Inconclusive(text.ToString());
        }
    }
}
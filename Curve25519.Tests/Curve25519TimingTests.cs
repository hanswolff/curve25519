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
            for (int i = 0; i < 255; i++)
            {
                byte[] privateKey = Curve25519.ClampPrivateKey(TestHelpers.GetUniformBytes((byte)i, 32));
                Curve25519.GetPublicKey(privateKey);

                Stopwatch stopwatch = Stopwatch.StartNew();

                for (int j = 0; j < 100; j++)
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
    }
}
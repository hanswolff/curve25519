using NUnit.Framework;

namespace Curve25519.Tests
{
    [TestFixture]
    public class Curve25519Tests
    {
        [Test]
        public void DiffieHellmanSuccess()
        {
            var random = TestHelpers.CreateSemiRandomGenerator(); // not truly random in case we need to reproduce test values

            for (var i = 0; i < 1000; i++)
            {
                var alicePrivate = Curve25519.ClampPrivateKey(TestHelpers.GetRandomBytes(random, 32));
                var alicePublic = Curve25519.GetPublicKey(alicePrivate);

                var bobPrivate = Curve25519.ClampPrivateKey(TestHelpers.GetRandomBytes(random, 32));
                var bobPublic = Curve25519.GetPublicKey(bobPrivate);

                var aliceShared = Curve25519.GetSharedSecret(alicePrivate, bobPublic);
                var bobShared = Curve25519.GetSharedSecret(bobPrivate, alicePublic);

                Assert.AreEqual(aliceShared, bobShared);
            }
        }

        [Test]
        public void DiffieHellmanFail()
        {
            var random = TestHelpers.CreateSemiRandomGenerator();
            for (var i = 0; i < 1000; i++)
            {
                var alicePrivate = Curve25519.ClampPrivateKey(TestHelpers.GetRandomBytes(random, 32));
                var alicePublic = Curve25519.GetPublicKey(alicePrivate);

                var bobPrivate = Curve25519.ClampPrivateKey(TestHelpers.GetRandomBytes(random, 32));
                var bobPublic = Curve25519.GetPublicKey(bobPrivate);

                var aliceShared = Curve25519.GetSharedSecret(alicePrivate, bobPublic);

                var alicePublicWithBitToggled = TestHelpers.ToggleBitInKey(alicePublic, random);
                var bobShared = Curve25519.GetSharedSecret(bobPrivate, alicePublicWithBitToggled);

                Assert.AreNotEqual(aliceShared, bobShared);
            }
        }
    }
}
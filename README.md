[Curve25519](http://cr.yp.to/ecdh.html) is an elliptic curve, 
developed by [Dan Bernstein](http://cr.yp.to/djb.html), for fast Diffie-Hellman key agreement.

#### Usage Example

	// what Alice does
	byte[] aliceRandomBytes = new byte[32];
	RNGCryptoServiceProvider.Create().GetBytes(aliceRandomBytes);

	byte[] alicePrivate = Curve25519.ClampPrivateKey(aliceRandomBytes);
	byte[] alicePublic = Curve25519.GetPublicKey(alicePrivate);

	// what Bob does
	byte[] bobRandomBytes = new byte[32];
	RNGCryptoServiceProvider.Create().GetBytes(bobRandomBytes);

	byte[] bobPrivate = Curve25519.ClampPrivateKey(bobRandomBytes);
	byte[] bobPublic = Curve25519.GetPublicKey(bobPrivate);

	// what Alice does with Bob's public key
	byte[] aliceShared = Curve25519.GetSharedSecret(alicePrivate, bobPublic);
	
	// what Bob does with Alice' public key
	byte[] bobShared = Curve25519.GetSharedSecret(bobPrivate, alicePublic);
	
	// aliceShared == bobShared

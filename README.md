[Curve25519](http://cr.yp.to/ecdh.html) is an elliptic curve, 
developed by [Dan Bernstein](http://cr.yp.to/djb.html), for fast Diffie-Hellman key agreement.

Generic 64-bit integer implementation of Curve25519 ECDH  
Written by Matthijs van Duin, 200608242056  
Original: http://cds.xs4all.nl:8081/ecdh/ (broken link)

Ported from C to Java by Dmitry Skiba [sahn0], 23/02/08.  
Original: http://code.google.com/p/curve25519-java/

Ported parts from Java to C# and refactored by Hans Wolff, 17/09/2013.
Original: https://github.com/hanswolff/curve25519/

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

#### NuGet Package

...can be downloaded from here:  
https://www.nuget.org/packages/Curve25519/

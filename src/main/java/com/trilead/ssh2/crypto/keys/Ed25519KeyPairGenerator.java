package com.trilead.ssh2.crypto.keys;

import com.google.crypto.tink.subtle.Ed25519Sign;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

/**
 * KeyPairGenerator implementation for Ed25519 keys.
 * <p>
 * Generates Ed25519 key pairs for SSH authentication and signing.
 *
 * @see Ed25519PublicKey
 * @see Ed25519PrivateKey
 */
public class Ed25519KeyPairGenerator extends KeyPairGeneratorSpi {
	@Override
	public void initialize(int keySize, SecureRandom secureRandom) {
		// ignored.
	}

	@Override
	public KeyPair generateKeyPair() {
		try {
			Ed25519Sign.KeyPair kp = Ed25519Sign.KeyPair.newKeyPair();
			return new KeyPair(new Ed25519PublicKey(kp.getPublicKey()), new Ed25519PrivateKey(kp.getPrivateKey()));
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}
}

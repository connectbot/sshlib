package com.trilead.ssh2.crypto.keys;

import com.google.crypto.tink.subtle.Ed25519Sign;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public class EdDSAKeyPairGenerator extends KeyPairGeneratorSpi {
	@Override
	public void initialize(int keySize, SecureRandom secureRandom) {
		// ignored.
	}

	@Override
	public KeyPair generateKeyPair() {
		try {
			Ed25519Sign.KeyPair kp = Ed25519Sign.KeyPair.newKeyPair();
			return new KeyPair(new EdDSAPublicKey(kp.getPublicKey()), new EdDSAPrivateKey(kp.getPrivateKey()));
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}
}

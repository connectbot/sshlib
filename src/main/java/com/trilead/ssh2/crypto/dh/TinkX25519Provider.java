package com.trilead.ssh2.crypto.dh;

import com.google.crypto.tink.subtle.X25519;

import java.security.InvalidKeyException;

/**
 * X25519 provider implementation using Google Tink.
 * This is the fallback implementation for platforms without native X25519 support.
 */
public class TinkX25519Provider implements X25519Provider {
	@Override
	public byte[] generatePrivateKey() {
		return X25519.generatePrivateKey();
	}

	@Override
	public byte[] publicFromPrivate(byte[] privateKey) throws InvalidKeyException {
		return X25519.publicFromPrivate(privateKey);
	}

	@Override
	public byte[] computeSharedSecret(byte[] privateKey, byte[] publicKey) throws InvalidKeyException {
		return X25519.computeSharedSecret(privateKey, publicKey);
	}
}

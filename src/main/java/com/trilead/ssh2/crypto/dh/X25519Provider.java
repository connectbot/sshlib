package com.trilead.ssh2.crypto.dh;

import java.security.InvalidKeyException;

/**
 * Interface for X25519 key exchange operations.
 * Implementations may use different underlying cryptographic libraries.
 */
public interface X25519Provider {
	int KEY_SIZE = 32;

	byte[] generatePrivateKey();

	byte[] publicFromPrivate(byte[] privateKey) throws InvalidKeyException;

	byte[] computeSharedSecret(byte[] privateKey, byte[] publicKey) throws InvalidKeyException;
}

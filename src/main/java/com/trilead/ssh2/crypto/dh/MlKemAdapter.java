package com.trilead.ssh2.crypto.dh;

import java.io.IOException;

/**
 * Interface for ML-KEM-768 operations.
 * Allows for multiple implementations (Java 23+ native KEM API or Kyber Kotlin fallback).
 */
public interface MlKemAdapter {

	/**
	 * Generate a new ML-KEM-768 key pair.
	 *
	 * @return the key pair
	 * @throws IOException if key generation fails
	 */
	MlKemKeyPair generateKeyPair() throws IOException;

	/**
	 * Encapsulate a shared secret using the given public key.
	 *
	 * @param publicKey the ML-KEM-768 public key (1184 bytes)
	 * @return the encapsulation result containing ciphertext and shared secret
	 * @throws IOException if encapsulation fails
	 */
	MlKemEncapsulationResult encapsulate(byte[] publicKey) throws IOException;

	/**
	 * Decapsulate a shared secret using the given private key and ciphertext.
	 *
	 * @param privateKey the ML-KEM-768 private key
	 * @param ciphertext the ML-KEM-768 ciphertext (1088 bytes)
	 * @return the shared secret (32 bytes)
	 * @throws IOException if decapsulation fails
	 */
	byte[] decapsulate(byte[] privateKey, byte[] ciphertext) throws IOException;

	/**
	 * Represents an ML-KEM key pair.
	 */
	interface MlKemKeyPair {
		byte[] getPublicKey();
		byte[] getPrivateKey();
	}

	/**
	 * Represents an ML-KEM encapsulation.
	 */
	interface MlKemEncapsulationResult {
		byte[] getCiphertext();
		byte[] getSharedSecret();
	}
}

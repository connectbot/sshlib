package com.trilead.ssh2.crypto.dh;

import asia.hombre.kyber.KyberCipherText;
import asia.hombre.kyber.KyberDecapsulationKey;
import asia.hombre.kyber.KyberEncapsulationKey;
import asia.hombre.kyber.KyberEncapsulationResult;
import asia.hombre.kyber.KyberKEMKeyPair;
import asia.hombre.kyber.KyberKeyGenerator;
import asia.hombre.kyber.KyberParameter;
import asia.hombre.kyber.exceptions.InvalidKyberKeyException;
import asia.hombre.kyber.exceptions.UnsupportedKyberVariantException;
import asia.hombre.kyber.interfaces.RandomProvider;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * ML-KEM adapter using Kyber Kotlin library as a fallback.
 * This implementation is used when Java 23+ native KEM API is not available (e.g., Android).
 */
public class KyberKotlinAdapter implements MlKemAdapter {

	private static final SecureRandomProvider RANDOM_PROVIDER = new SecureRandomProvider();

	@Override
	public MlKemKeyPair generateKeyPair() throws IOException {
		try {
			KyberKEMKeyPair keyPair = KyberKeyGenerator.generate(KyberParameter.ML_KEM_768, RANDOM_PROVIDER);

			byte[] publicKey = keyPair.getEncapsulationKey().getFullBytes();
			byte[] privateKey = keyPair.getDecapsulationKey().getFullBytes();

			return new KyberKotlinKeyPair(publicKey, privateKey);
		} catch (Exception e) {
			throw new IOException("Failed to generate Kyber key pair", e);
		}
	}

	@Override
	public MlKemEncapsulationResult encapsulate(byte[] publicKey) throws IOException {
		try {
			KyberEncapsulationKey encapsKey = KyberEncapsulationKey.fromBytes(publicKey);
			KyberEncapsulationResult result = encapsKey.encapsulate(RANDOM_PROVIDER);

			byte[] ciphertext = result.getCipherText().getFullBytes();
			byte[] sharedSecret = result.getSharedSecretKey();

			return new KyberKotlinEncapsulationResult(ciphertext, sharedSecret);
		} catch (UnsupportedKyberVariantException | InvalidKyberKeyException e) {
			throw new IOException("Kyber encapsulation failed", e);
		}
	}

	@Override
	public byte[] decapsulate(byte[] privateKey, byte[] ciphertext) throws IOException {
		try {
			KyberDecapsulationKey decapsKey = KyberDecapsulationKey.fromBytes(privateKey);
			KyberCipherText cipherText = KyberCipherText.fromBytes(ciphertext);

			return decapsKey.decapsulate(cipherText);
		} catch (UnsupportedKyberVariantException | InvalidKyberKeyException e) {
			throw new IOException("Kyber decapsulation failed", e);
		}
	}

	private static class KyberKotlinKeyPair implements MlKemKeyPair {
		private final byte[] publicKey;
		private final byte[] privateKey;

		KyberKotlinKeyPair(byte[] publicKey, byte[] privateKey) {
			this.publicKey = publicKey;
			this.privateKey = privateKey;
		}

		@Override
		public byte[] getPublicKey() {
			return publicKey;
		}

		@Override
		public byte[] getPrivateKey() {
			return privateKey;
		}
	}

	private static class KyberKotlinEncapsulationResult implements MlKemEncapsulationResult {
		private final byte[] ciphertext;
		private final byte[] sharedSecret;

		KyberKotlinEncapsulationResult(byte[] ciphertext, byte[] sharedSecret) {
			this.ciphertext = ciphertext;
			this.sharedSecret = sharedSecret;
		}

		@Override
		public byte[] getCiphertext() {
			return ciphertext;
		}

		@Override
		public byte[] getSharedSecret() {
			return sharedSecret;
		}
	}

	private static class SecureRandomProvider implements RandomProvider {
		private final SecureRandom secureRandom;

		SecureRandomProvider() {
			this.secureRandom = new SecureRandom();
		}

		@Override
		public void fillWithRandom(byte[] bytes) {
			secureRandom.nextBytes(bytes);
		}
	}
}

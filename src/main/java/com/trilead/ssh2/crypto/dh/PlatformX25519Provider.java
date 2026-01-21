package com.trilead.ssh2.crypto.dh;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

import javax.crypto.KeyAgreement;

/**
 * X25519 provider implementation using platform-native APIs (Java 11+/Android API 33+).
 */
public class PlatformX25519Provider implements X25519Provider {
	private static final String ALGORITHM = "X25519";
	private static final NamedParameterSpec X25519_SPEC = new NamedParameterSpec(ALGORITHM);

	private final KeyPairGenerator keyPairGenerator;
	private final KeyFactory keyFactory;

	public PlatformX25519Provider() {
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
			keyFactory = KeyFactory.getInstance(ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("X25519 not available on this platform", e);
		}
	}

	@Override
	public byte[] generatePrivateKey() {
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return extractPrivateKeyBytes(keyPair.getPrivate());
	}

	@Override
	public byte[] publicFromPrivate(byte[] privateKey) throws InvalidKeyException {
		byte[] pubKeyBytes = new byte[KEY_SIZE];
		computePublicFromPrivate(privateKey, pubKeyBytes);
		return pubKeyBytes;
	}

	private void computePublicFromPrivate(byte[] privateKey, byte[] publicKey) throws InvalidKeyException {
		try {
			PrivateKey privKey = createPrivateKey(privateKey);
			KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM);
			ka.init(privKey);

			XECPublicKeySpec basePointSpec = new XECPublicKeySpec(X25519_SPEC, BigInteger.valueOf(9));
			PublicKey basePoint = keyFactory.generatePublic(basePointSpec);
			ka.doPhase(basePoint, true);
			byte[] result = ka.generateSecret();
			System.arraycopy(result, 0, publicKey, 0, KEY_SIZE);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new InvalidKeyException("X25519 not available", e);
		}
	}

	@Override
	public byte[] computeSharedSecret(byte[] privateKey, byte[] publicKey) throws InvalidKeyException {
		try {
			PrivateKey privKey = createPrivateKey(privateKey);
			PublicKey pubKey = createPublicKey(publicKey);

			KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM);
			keyAgreement.init(privKey);
			keyAgreement.doPhase(pubKey, true);

			return keyAgreement.generateSecret();
		} catch (NoSuchAlgorithmException e) {
			throw new InvalidKeyException("X25519 not available", e);
		}
	}

	private PrivateKey createPrivateKey(byte[] keyBytes) throws InvalidKeyException {
		try {
			XECPrivateKeySpec spec = new XECPrivateKeySpec(X25519_SPEC, keyBytes.clone());
			return keyFactory.generatePrivate(spec);
		} catch (InvalidKeySpecException e) {
			throw new InvalidKeyException("Invalid private key", e);
		}
	}

	private PublicKey createPublicKey(byte[] keyBytes) throws InvalidKeyException {
		try {
			BigInteger u = decodeLittleEndian(keyBytes);
			XECPublicKeySpec spec = new XECPublicKeySpec(X25519_SPEC, u);
			return keyFactory.generatePublic(spec);
		} catch (InvalidKeySpecException e) {
			throw new InvalidKeyException("Invalid public key", e);
		}
	}

	private byte[] extractPrivateKeyBytes(PrivateKey privateKey) {
		try {
			XECPrivateKeySpec spec = keyFactory.getKeySpec(privateKey, XECPrivateKeySpec.class);
			byte[] scalar = spec.getScalar();
			if (scalar == null) {
				throw new IllegalStateException("Private key scalar not available");
			}
			if (scalar.length == KEY_SIZE) {
				return scalar;
			}
			byte[] padded = new byte[KEY_SIZE];
			System.arraycopy(scalar, 0, padded, KEY_SIZE - scalar.length, scalar.length);
			return padded;
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException("Failed to extract private key bytes", e);
		}
	}

	private static BigInteger decodeLittleEndian(byte[] bytes) {
		byte[] reversed = new byte[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			reversed[i] = bytes[bytes.length - 1 - i];
		}
		return new BigInteger(1, reversed);
	}
}

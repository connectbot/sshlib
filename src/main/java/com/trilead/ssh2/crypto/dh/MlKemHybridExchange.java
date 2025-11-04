package com.trilead.ssh2.crypto.dh;

import com.google.crypto.tink.subtle.X25519;
import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * ML-KEM-768 hybrid key exchange implementation (mlkem768x25519-sha256).
 * Combines post-quantum ML-KEM-768 with classical X25519 key exchange.
 * Uses reflection to access Java 23+ KEM APIs while maintaining compatibility with Java 11+.
 * Implements draft-ietf-sshm-mlkem-hybrid-kex-03 specification.
 */
public class MlKemHybridExchange extends GenericDhExchange {

	public static final String NAME = "mlkem768x25519-sha256";
	private static final int MLKEM768_PUBLIC_KEY_SIZE = 1184;
	private static final int MLKEM768_CIPHERTEXT_SIZE = 1088;
	private static final int MLKEM768_SHARED_SECRET_SIZE = 32;
	private static final int X25519_KEY_SIZE = 32;

	private byte[] mlkemPublicKey;
	private byte[] mlkemPrivateKeyEncoded;
	private byte[] x25519PublicKey;
	private byte[] x25519PrivateKey;

	private byte[] mlkemSharedSecret;
	private byte[] x25519SharedSecret;
	private byte[] serverX25519PublicKey;
	private byte[] serverReply;
	private byte[] hybridSharedSecretK;

	private Object kemInstance;

	public MlKemHybridExchange() {
		super();
	}

	@Override
	public void init(String name) throws IOException {
		if (!NAME.equals(name)) {
			throw new IOException("Invalid algorithm: " + name);
		}

		try {
			KeyPairGenerator mlkemKpg = KeyPairGenerator.getInstance("ML-KEM-768");
			KeyPair mlkemKeyPair = mlkemKpg.generateKeyPair();
			byte[] x509Encoded = mlkemKeyPair.getPublic().getEncoded();
			mlkemPublicKey = extractRawMlKemPublicKey(x509Encoded);
			mlkemPrivateKeyEncoded = mlkemKeyPair.getPrivate().getEncoded();

			if (mlkemPublicKey.length != MLKEM768_PUBLIC_KEY_SIZE) {
				throw new IOException(
						"Unexpected ML-KEM-768 public key size: "
								+ mlkemPublicKey.length
								+ " (expected "
								+ MLKEM768_PUBLIC_KEY_SIZE
								+ ")");
			}

			x25519PrivateKey = X25519.generatePrivateKey();
			x25519PublicKey = X25519.publicFromPrivate(x25519PrivateKey);

			if (x25519PublicKey.length != X25519_KEY_SIZE) {
				throw new IOException(
						"Unexpected X25519 public key size: "
								+ x25519PublicKey.length
								+ " (expected "
								+ X25519_KEY_SIZE
								+ ")");
			}

		} catch (NoSuchAlgorithmException e) {
			throw new IOException("ML-KEM-768 or X25519 not available", e);
		} catch (InvalidKeyException e) {
			throw new IOException("Failed to generate key pair", e);
		}
	}

	@Override
	public byte[] getE() {
		byte[] init = new byte[mlkemPublicKey.length + x25519PublicKey.length];
		System.arraycopy(mlkemPublicKey, 0, init, 0, mlkemPublicKey.length);
		System.arraycopy(
				x25519PublicKey, 0, init, mlkemPublicKey.length, x25519PublicKey.length);
		return init;
	}

	@Override
	protected byte[] getServerE() {
		return serverReply != null ? serverReply.clone() : new byte[0];
	}

	@Override
	public void setF(byte[] f) throws IOException {
		if (f.length != MLKEM768_CIPHERTEXT_SIZE + X25519_KEY_SIZE) {
			throw new IOException(
					"Invalid S_REPLY length: "
							+ f.length
							+ " (expected "
							+ (MLKEM768_CIPHERTEXT_SIZE + X25519_KEY_SIZE)
							+ ")");
		}

		serverReply = f.clone();

		try {
			byte[] mlkemCiphertext = new byte[MLKEM768_CIPHERTEXT_SIZE];
			System.arraycopy(f, 0, mlkemCiphertext, 0, MLKEM768_CIPHERTEXT_SIZE);

			serverX25519PublicKey = new byte[X25519_KEY_SIZE];
			System.arraycopy(f, MLKEM768_CIPHERTEXT_SIZE, serverX25519PublicKey, 0, X25519_KEY_SIZE);

			mlkemSharedSecret = performMlKemDecapsulation(mlkemCiphertext);

			x25519SharedSecret = X25519.computeSharedSecret(x25519PrivateKey, serverX25519PublicKey);
			validateX25519SharedSecret(x25519SharedSecret);

			byte[] combined = new byte[MLKEM768_SHARED_SECRET_SIZE + X25519_KEY_SIZE];
			System.arraycopy(mlkemSharedSecret, 0, combined, 0, MLKEM768_SHARED_SECRET_SIZE);
			System.arraycopy(x25519SharedSecret, 0, combined, MLKEM768_SHARED_SECRET_SIZE, X25519_KEY_SIZE);

			hybridSharedSecretK = computeHybridSharedSecret(combined);
			sharedSecret = new BigInteger(1, hybridSharedSecretK);

		} catch (InvalidKeyException e) {
			throw new IOException("X25519 key agreement failed", e);
		} catch (Exception e) {
			throw new IOException("ML-KEM decapsulation or key agreement failed", e);
		}
	}

	private byte[] performMlKemDecapsulation(byte[] ciphertext) throws IOException {
		try {
			if (kemInstance == null) {
				Class<?> kemClass = Class.forName("javax.crypto.KEM");
				Method getInstance = kemClass.getMethod("getInstance", String.class);
				kemInstance = getInstance.invoke(null, "ML-KEM");
			}

			KeyFactory kf = KeyFactory.getInstance("ML-KEM");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(mlkemPrivateKeyEncoded);
			PrivateKey mlkemPrivateKey = kf.generatePrivate(privateKeySpec);

			Class<?> kemClass = Class.forName("javax.crypto.KEM");
			Method newDecapsulator = kemClass.getMethod("newDecapsulator", PrivateKey.class);
			Object decapsulator = newDecapsulator.invoke(kemInstance, mlkemPrivateKey);

			Class<?> decapsulatorClass = Class.forName("javax.crypto.KEM$Decapsulator");
			Method decapsulateMethod = decapsulatorClass.getMethod("decapsulate", byte[].class);
			Object secretKey = decapsulateMethod.invoke(decapsulator, ciphertext);

			javax.crypto.SecretKey sk = (javax.crypto.SecretKey) secretKey;
			return sk.getEncoded();

		} catch (ClassNotFoundException e) {
			throw new IOException("ML-KEM not available (Java 23+ required)", e);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("ML-KEM not available", e);
		} catch (Exception e) {
			throw new IOException("ML-KEM decapsulation failed", e);
		}
	}

	private void validateX25519SharedSecret(byte[] sharedSecret) throws IOException {
		int allBytes = 0;
		for (int i = 0; i < sharedSecret.length; i++) {
			allBytes |= sharedSecret[i];
		}
		if (allBytes == 0) {
			throw new IOException("Invalid X25519 shared secret; all zeroes");
		}
	}

	private byte[] computeHybridSharedSecret(byte[] combined) throws IOException {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			return md.digest(combined);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("SHA-256 not available", e);
		}
	}

	@Override
	public String getHashAlgo() {
		return "SHA-256";
	}

	@Override
	public byte[] getK() {
		if (hybridSharedSecretK == null) {
			throw new IllegalStateException("Shared secret not yet known, need f first!");
		}
		return hybridSharedSecretK.clone();
	}

	private static byte[] extractRawMlKemPublicKey(byte[] x509Encoded) throws IOException {
		if (x509Encoded.length < 22) {
			throw new IOException("X.509 encoded ML-KEM public key too short");
		}

		if (x509Encoded[0] != 0x30) {
			throw new IOException("Invalid X.509 encoding: expected SEQUENCE tag");
		}

		if (x509Encoded[17] != 0x03) {
			throw new IOException("Invalid X.509 encoding: BIT STRING not found at expected position");
		}

		if (x509Encoded[21] != 0x00) {
			throw new IOException("Invalid X.509 encoding: unexpected unused bits in BIT STRING");
		}

		byte[] rawKey = new byte[MLKEM768_PUBLIC_KEY_SIZE];
		System.arraycopy(x509Encoded, 22, rawKey, 0, MLKEM768_PUBLIC_KEY_SIZE);
		return rawKey;
	}
}

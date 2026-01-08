/*
 * ConnectBot: simple, powerful, open-source SSH client for Android
 * Copyright 2007 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.trilead.ssh2.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.trilead.ssh2.crypto.keys.Ed25519PrivateKey;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;
import com.trilead.ssh2.packets.TypesWriter;
import com.trilead.ssh2.signature.ECDSASHA2Verify;

import org.mindrot.jbcrypt.BCrypt;

/**
 * OpenSSH Key Encoder for exporting SSH keys in OpenSSH format.
 * <p>
 * This class provides methods to export RSA, DSA, EC, and Ed25519 key pairs
 * in the OpenSSH private key format (openssh-key-v1), with optional
 * passphrase-based encryption using AES-256-CTR and bcrypt_pbkdf.
 * <p>
 * The OpenSSH format uses the header "-----BEGIN OPENSSH PRIVATE KEY-----"
 * and is the default format used by modern versions of ssh-keygen.
 * <p>
 * This is the encoding counterpart to the OpenSSH decoding in
 * {@link OpenSSHKeyDecoder}.
 *
 * @author Kenny Root
 */
public class OpenSSHKeyEncoder {

	private static final String OPENSSH_PRIVATE_KEY_START = "-----BEGIN OPENSSH PRIVATE KEY-----";
	private static final String OPENSSH_PRIVATE_KEY_END = "-----END OPENSSH PRIVATE KEY-----";
	private static final String OPENSSH_KEY_V1_MAGIC = "openssh-key-v1\0";
	private static final String ED25519_KEY_TYPE = "ssh-ed25519";

	// OpenSSH encrypted key constants
	private static final String OPENSSH_CIPHER_AES256_CTR = "aes256-ctr";
	private static final String OPENSSH_KDF_BCRYPT = "bcrypt";
	private static final int OPENSSH_BCRYPT_SALT_SIZE = 16;
	private static final int OPENSSH_BCRYPT_ROUNDS = 16;
	private static final int OPENSSH_AES_KEY_SIZE = 32; // 256 bits
	private static final int OPENSSH_AES_IV_SIZE = 16; // 128 bits
	private static final int OPENSSH_AES_BLOCK_SIZE = 16;

	/**
	 * Derives a key and IV from a passphrase using bcrypt_pbkdf for OpenSSH
	 * encrypted keys.
	 *
	 * @param passphrase The passphrase to derive from
	 * @param salt       The salt (typically 16 bytes)
	 * @param rounds     Number of bcrypt rounds (typically 16)
	 * @return A byte array containing the key (32 bytes) followed by IV (16 bytes)
	 */
	private static byte[] deriveOpenSSHKey(String passphrase, byte[] salt, int rounds) {
		int keyLength = OPENSSH_AES_KEY_SIZE + OPENSSH_AES_IV_SIZE; // 48 bytes
		byte[] output = new byte[keyLength];
		new BCrypt().pbkdf(passphrase.getBytes(StandardCharsets.UTF_8), salt, rounds, output);
		return output;
	}

	/**
	 * Encrypts data using AES-256-CTR for OpenSSH encrypted key format.
	 *
	 * @param data The plaintext data to encrypt
	 * @param key  The 32-byte AES key
	 * @param iv   The 16-byte IV
	 * @return The encrypted data
	 * @throws IOException if encryption fails
	 */
	private static byte[] encryptAesCtr(byte[] data, byte[] key, byte[] iv) throws IOException {
		try {
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | javax.crypto.IllegalBlockSizeException
				| javax.crypto.BadPaddingException e) {
			throw new IOException("Encryption failed", e);
		}
	}

	/**
	 * Exports an Ed25519 key pair in OpenSSH format (unencrypted).
	 *
	 * @param privateKey The Ed25519 private key
	 * @param publicKey  The Ed25519 public key
	 * @param comment    Optional comment (typically the key nickname)
	 * @return The key in OpenSSH PEM format
	 */
	public static String exportOpenSSHEd25519(
			Ed25519PrivateKey privateKey,
			Ed25519PublicKey publicKey,
			String comment) {
		return exportOpenSSHEd25519(privateKey, publicKey, comment, null);
	}

	/**
	 * Exports an Ed25519 key pair in OpenSSH format.
	 * This is the standard format used by ssh-keygen and compatible with other SSH
	 * tools.
	 *
	 * @param privateKey The Ed25519 private key
	 * @param publicKey  The Ed25519 public key
	 * @param comment    Optional comment (typically the key nickname)
	 * @param passphrase Optional passphrase for encryption. If null or empty, key
	 *                   is unencrypted.
	 * @return The key in OpenSSH PEM format
	 */
	public static String exportOpenSSHEd25519(
			Ed25519PrivateKey privateKey,
			Ed25519PublicKey publicKey,
			String comment,
			String passphrase) {
		boolean encrypted = passphrase != null && !passphrase.isEmpty();
		TypesWriter tw = new TypesWriter();

		// Magic header: "openssh-key-v1\0"
		tw.writeBytes(OPENSSH_KEY_V1_MAGIC.getBytes(StandardCharsets.US_ASCII));

		// Generate salt for encryption if needed
		byte[] salt = null;
		if (encrypted) {
			salt = new byte[OPENSSH_BCRYPT_SALT_SIZE];
			new SecureRandom().nextBytes(salt);
		}

		// Cipher name
		tw.writeString(encrypted ? OPENSSH_CIPHER_AES256_CTR : "none");

		// KDF name
		tw.writeString(encrypted ? OPENSSH_KDF_BCRYPT : "none");

		// KDF options
		if (encrypted && salt != null) {
			TypesWriter kdfOptions = new TypesWriter();
			kdfOptions.writeString(salt, 0, salt.length);
			kdfOptions.writeUINT32(OPENSSH_BCRYPT_ROUNDS);
			tw.writeString(kdfOptions.getBytes(), 0, kdfOptions.length());
		} else {
			tw.writeString("");
		}

		// Number of keys: 1
		tw.writeUINT32(1);

		// Public key blob
		byte[] publicKeyBytes = publicKey.getAbyte();
		TypesWriter pubKeyBlob = new TypesWriter();
		pubKeyBlob.writeString(ED25519_KEY_TYPE);
		pubKeyBlob.writeString(publicKeyBytes, 0, publicKeyBytes.length);
		tw.writeString(pubKeyBlob.getBytes(), 0, pubKeyBlob.length());

		// Private key section
		TypesWriter privateSection = new TypesWriter();

		// Check integers (random, must match for verification)
		int checkInt = new SecureRandom().nextInt();
		privateSection.writeUINT32(checkInt);
		privateSection.writeUINT32(checkInt);

		// Key type
		privateSection.writeString(ED25519_KEY_TYPE);

		// Public key
		privateSection.writeString(publicKeyBytes, 0, publicKeyBytes.length);

		// Private key: 64 bytes (32-byte seed + 32-byte public key)
		byte[] seed = privateKey.getSeed();
		byte[] privateKeyData = new byte[64];
		System.arraycopy(seed, 0, privateKeyData, 0, 32);
		System.arraycopy(publicKeyBytes, 0, privateKeyData, 32, 32);
		privateSection.writeString(privateKeyData, 0, privateKeyData.length);

		// Comment
		privateSection.writeString(comment != null ? comment : "");

		// Padding to block size (16 for encrypted, 8 for unencrypted)
		int blockSize = encrypted ? OPENSSH_AES_BLOCK_SIZE : 8;
		int paddingNeeded = blockSize - (privateSection.length() % blockSize);
		if (paddingNeeded == blockSize)
			paddingNeeded = 0;
		for (int i = 1; i <= paddingNeeded; i++) {
			privateSection.writeByte(i);
		}

		// Encrypt if passphrase provided
		byte[] privateSectionBytes;
		if (encrypted && salt != null) {
			byte[] derivedKey = deriveOpenSSHKey(passphrase, salt, OPENSSH_BCRYPT_ROUNDS);
			byte[] key = java.util.Arrays.copyOfRange(derivedKey, 0, OPENSSH_AES_KEY_SIZE);
			byte[] iv = java.util.Arrays.copyOfRange(derivedKey, OPENSSH_AES_KEY_SIZE,
					OPENSSH_AES_KEY_SIZE + OPENSSH_AES_IV_SIZE);
			try {
				privateSectionBytes = encryptAesCtr(privateSection.getBytes(), key, iv);
			} catch (IOException e) {
				throw new RuntimeException("Encryption failed", e);
			}
		} else {
			privateSectionBytes = privateSection.getBytes();
		}

		// Write the private section
		tw.writeString(privateSectionBytes, 0, privateSectionBytes.length);

		return formatOpenSSHKey(tw.getBytes());
	}

	/**
	 * Exports an RSA key pair in OpenSSH format (unencrypted).
	 *
	 * @param privateKey The RSA private key (must be RSAPrivateCrtKey)
	 * @param publicKey  The RSA public key
	 * @param comment    Optional comment
	 * @return The key in OpenSSH format
	 */
	public static String exportOpenSSHRSA(
			RSAPrivateCrtKey privateKey,
			RSAPublicKey publicKey,
			String comment) {
		return exportOpenSSHRSA(privateKey, publicKey, comment, null);
	}

	/**
	 * Exports an RSA key pair in OpenSSH format.
	 *
	 * @param privateKey The RSA private key (must be RSAPrivateCrtKey)
	 * @param publicKey  The RSA public key
	 * @param comment    Optional comment
	 * @param passphrase Optional passphrase for encryption. If null or empty, key
	 *                   is unencrypted.
	 * @return The key in OpenSSH format
	 */
	public static String exportOpenSSHRSA(
			RSAPrivateCrtKey privateKey,
			RSAPublicKey publicKey,
			String comment,
			String passphrase) {
		boolean encrypted = passphrase != null && !passphrase.isEmpty();
		TypesWriter tw = new TypesWriter();

		// Magic header
		tw.writeBytes(OPENSSH_KEY_V1_MAGIC.getBytes(StandardCharsets.US_ASCII));

		// Generate salt for encryption if needed
		byte[] salt = null;
		if (encrypted) {
			salt = new byte[OPENSSH_BCRYPT_SALT_SIZE];
			new SecureRandom().nextBytes(salt);
		}

		// Cipher name
		tw.writeString(encrypted ? OPENSSH_CIPHER_AES256_CTR : "none");

		// KDF name
		tw.writeString(encrypted ? OPENSSH_KDF_BCRYPT : "none");

		// KDF options
		if (encrypted && salt != null) {
			TypesWriter kdfOptions = new TypesWriter();
			kdfOptions.writeString(salt, 0, salt.length);
			kdfOptions.writeUINT32(OPENSSH_BCRYPT_ROUNDS);
			tw.writeString(kdfOptions.getBytes(), 0, kdfOptions.length());
		} else {
			tw.writeString("");
		}

		// Number of keys
		tw.writeUINT32(1);

		// Public key blob: ssh-rsa, e, n
		TypesWriter pubKeyBlob = new TypesWriter();
		pubKeyBlob.writeString("ssh-rsa");
		pubKeyBlob.writeMPInt(publicKey.getPublicExponent());
		pubKeyBlob.writeMPInt(publicKey.getModulus());
		tw.writeString(pubKeyBlob.getBytes(), 0, pubKeyBlob.length());

		// Private key section
		TypesWriter privateSection = new TypesWriter();
		int checkInt = new SecureRandom().nextInt();
		privateSection.writeUINT32(checkInt);
		privateSection.writeUINT32(checkInt);

		privateSection.writeString("ssh-rsa");
		privateSection.writeMPInt(publicKey.getModulus()); // n
		privateSection.writeMPInt(publicKey.getPublicExponent()); // e
		privateSection.writeMPInt(privateKey.getPrivateExponent()); // d
		privateSection.writeMPInt(privateKey.getCrtCoefficient()); // iqmp (q^-1 mod p)
		privateSection.writeMPInt(privateKey.getPrimeP()); // p
		privateSection.writeMPInt(privateKey.getPrimeQ()); // q

		privateSection.writeString(comment != null ? comment : "");

		// Padding to block size (16 for encrypted, 8 for unencrypted)
		int blockSize = encrypted ? OPENSSH_AES_BLOCK_SIZE : 8;
		int paddingNeeded = blockSize - (privateSection.length() % blockSize);
		if (paddingNeeded == blockSize)
			paddingNeeded = 0;
		for (int i = 1; i <= paddingNeeded; i++) {
			privateSection.writeByte(i);
		}

		// Encrypt if passphrase provided
		byte[] privateSectionBytes;
		if (encrypted && salt != null) {
			byte[] derivedKey = deriveOpenSSHKey(passphrase, salt, OPENSSH_BCRYPT_ROUNDS);
			byte[] key = java.util.Arrays.copyOfRange(derivedKey, 0, OPENSSH_AES_KEY_SIZE);
			byte[] iv = java.util.Arrays.copyOfRange(derivedKey, OPENSSH_AES_KEY_SIZE,
					OPENSSH_AES_KEY_SIZE + OPENSSH_AES_IV_SIZE);
			try {
				privateSectionBytes = encryptAesCtr(privateSection.getBytes(), key, iv);
			} catch (IOException e) {
				throw new RuntimeException("Encryption failed", e);
			}
		} else {
			privateSectionBytes = privateSection.getBytes();
		}

		tw.writeString(privateSectionBytes, 0, privateSectionBytes.length);

		return formatOpenSSHKey(tw.getBytes());
	}

	/**
	 * Exports a DSA key pair in OpenSSH format (unencrypted).
	 *
	 * @param privateKey The DSA private key
	 * @param publicKey  The DSA public key
	 * @param comment    Optional comment
	 * @return The key in OpenSSH format
	 */
	public static String exportOpenSSHDSA(
			DSAPrivateKey privateKey,
			DSAPublicKey publicKey,
			String comment) {
		return exportOpenSSHDSA(privateKey, publicKey, comment, null);
	}

	/**
	 * Exports a DSA key pair in OpenSSH format.
	 *
	 * @param privateKey The DSA private key
	 * @param publicKey  The DSA public key
	 * @param comment    Optional comment
	 * @param passphrase Optional passphrase for encryption. If null or empty, key
	 *                   is unencrypted.
	 * @return The key in OpenSSH format
	 */
	public static String exportOpenSSHDSA(
			DSAPrivateKey privateKey,
			DSAPublicKey publicKey,
			String comment,
			String passphrase) {
		boolean encrypted = passphrase != null && !passphrase.isEmpty();
		TypesWriter tw = new TypesWriter();

		// Magic header
		tw.writeBytes(OPENSSH_KEY_V1_MAGIC.getBytes(StandardCharsets.US_ASCII));

		// Generate salt for encryption if needed
		byte[] salt = null;
		if (encrypted) {
			salt = new byte[OPENSSH_BCRYPT_SALT_SIZE];
			new SecureRandom().nextBytes(salt);
		}

		// Cipher name
		tw.writeString(encrypted ? OPENSSH_CIPHER_AES256_CTR : "none");

		// KDF name
		tw.writeString(encrypted ? OPENSSH_KDF_BCRYPT : "none");

		// KDF options
		if (encrypted && salt != null) {
			TypesWriter kdfOptions = new TypesWriter();
			kdfOptions.writeString(salt, 0, salt.length);
			kdfOptions.writeUINT32(OPENSSH_BCRYPT_ROUNDS);
			tw.writeString(kdfOptions.getBytes(), 0, kdfOptions.length());
		} else {
			tw.writeString("");
		}

		// Number of keys
		tw.writeUINT32(1);

		java.security.interfaces.DSAParams params = publicKey.getParams();

		// Public key blob: ssh-dss, p, q, g, y
		TypesWriter pubKeyBlob = new TypesWriter();
		pubKeyBlob.writeString("ssh-dss");
		pubKeyBlob.writeMPInt(params.getP());
		pubKeyBlob.writeMPInt(params.getQ());
		pubKeyBlob.writeMPInt(params.getG());
		pubKeyBlob.writeMPInt(publicKey.getY());
		tw.writeString(pubKeyBlob.getBytes(), 0, pubKeyBlob.length());

		// Private key section
		TypesWriter privateSection = new TypesWriter();
		int checkInt = new SecureRandom().nextInt();
		privateSection.writeUINT32(checkInt);
		privateSection.writeUINT32(checkInt);

		privateSection.writeString("ssh-dss");
		privateSection.writeMPInt(params.getP());
		privateSection.writeMPInt(params.getQ());
		privateSection.writeMPInt(params.getG());
		privateSection.writeMPInt(publicKey.getY());
		privateSection.writeMPInt(privateKey.getX());

		privateSection.writeString(comment != null ? comment : "");

		// Padding to block size (16 for encrypted, 8 for unencrypted)
		int blockSize = encrypted ? OPENSSH_AES_BLOCK_SIZE : 8;
		int paddingNeeded = blockSize - (privateSection.length() % blockSize);
		if (paddingNeeded == blockSize)
			paddingNeeded = 0;
		for (int i = 1; i <= paddingNeeded; i++) {
			privateSection.writeByte(i);
		}

		// Encrypt if passphrase provided
		byte[] privateSectionBytes;
		if (encrypted && salt != null) {
			byte[] derivedKey = deriveOpenSSHKey(passphrase, salt, OPENSSH_BCRYPT_ROUNDS);
			byte[] key = java.util.Arrays.copyOfRange(derivedKey, 0, OPENSSH_AES_KEY_SIZE);
			byte[] iv = java.util.Arrays.copyOfRange(derivedKey, OPENSSH_AES_KEY_SIZE,
					OPENSSH_AES_KEY_SIZE + OPENSSH_AES_IV_SIZE);
			try {
				privateSectionBytes = encryptAesCtr(privateSection.getBytes(), key, iv);
			} catch (IOException e) {
				throw new RuntimeException("Encryption failed", e);
			}
		} else {
			privateSectionBytes = privateSection.getBytes();
		}

		tw.writeString(privateSectionBytes, 0, privateSectionBytes.length);

		return formatOpenSSHKey(tw.getBytes());
	}

	/**
	 * Exports an EC key pair in OpenSSH format (unencrypted).
	 *
	 * @param privateKey The EC private key
	 * @param publicKey  The EC public key
	 * @param comment    Optional comment
	 * @return The key in OpenSSH format
	 * @throws InvalidKeyException if the EC curve is not supported
	 */
	public static String exportOpenSSHEC(
			ECPrivateKey privateKey,
			ECPublicKey publicKey,
			String comment) throws InvalidKeyException {
		return exportOpenSSHEC(privateKey, publicKey, comment, null);
	}

	/**
	 * Exports an EC key pair in OpenSSH format.
	 *
	 * @param privateKey The EC private key
	 * @param publicKey  The EC public key
	 * @param comment    Optional comment
	 * @param passphrase Optional passphrase for encryption. If null or empty, key
	 *                   is unencrypted.
	 * @return The key in OpenSSH format
	 * @throws InvalidKeyException if the EC curve is not supported
	 */
	public static String exportOpenSSHEC(
			ECPrivateKey privateKey,
			ECPublicKey publicKey,
			String comment,
			String passphrase) throws InvalidKeyException {
		boolean encrypted = passphrase != null && !passphrase.isEmpty();
		TypesWriter tw = new TypesWriter();

		// Determine curve name and key type
		int fieldSize = publicKey.getParams().getCurve().getField().getFieldSize();
		String curveName;
		String keyType;
		switch (fieldSize) {
			case 256:
				curveName = "nistp256";
				keyType = "ecdsa-sha2-nistp256";
				break;
			case 384:
				curveName = "nistp384";
				keyType = "ecdsa-sha2-nistp384";
				break;
			case 521:
				curveName = "nistp521";
				keyType = "ecdsa-sha2-nistp521";
				break;
			default:
				throw new InvalidKeyException("Unsupported EC curve size: " + fieldSize);
		}

		// Magic header
		tw.writeBytes(OPENSSH_KEY_V1_MAGIC.getBytes(StandardCharsets.US_ASCII));

		// Generate salt for encryption if needed
		byte[] salt = null;
		if (encrypted) {
			salt = new byte[OPENSSH_BCRYPT_SALT_SIZE];
			new SecureRandom().nextBytes(salt);
		}

		// Cipher name
		tw.writeString(encrypted ? OPENSSH_CIPHER_AES256_CTR : "none");

		// KDF name
		tw.writeString(encrypted ? OPENSSH_KDF_BCRYPT : "none");

		// KDF options
		if (encrypted && salt != null) {
			TypesWriter kdfOptions = new TypesWriter();
			kdfOptions.writeString(salt, 0, salt.length);
			kdfOptions.writeUINT32(OPENSSH_BCRYPT_ROUNDS);
			tw.writeString(kdfOptions.getBytes(), 0, kdfOptions.length());
		} else {
			tw.writeString("");
		}

		// Number of keys
		tw.writeUINT32(1);

		// Encode public key point in uncompressed format (0x04 || x || y)
		byte[] publicPoint = ECDSASHA2Verify.encodeECPoint(publicKey.getW(), publicKey.getParams().getCurve());

		// Public key blob: key_type, curve_name, Q
		TypesWriter pubKeyBlob = new TypesWriter();
		pubKeyBlob.writeString(keyType);
		pubKeyBlob.writeString(curveName);
		pubKeyBlob.writeString(publicPoint, 0, publicPoint.length);
		tw.writeString(pubKeyBlob.getBytes(), 0, pubKeyBlob.length());

		// Private key section
		TypesWriter privateSection = new TypesWriter();
		int checkInt = new SecureRandom().nextInt();
		privateSection.writeUINT32(checkInt);
		privateSection.writeUINT32(checkInt);

		privateSection.writeString(keyType);
		privateSection.writeString(curveName);
		privateSection.writeString(publicPoint, 0, publicPoint.length);
		privateSection.writeMPInt(privateKey.getS());

		privateSection.writeString(comment != null ? comment : "");

		// Padding to block size (16 for encrypted, 8 for unencrypted)
		int blockSize = encrypted ? OPENSSH_AES_BLOCK_SIZE : 8;
		int paddingNeeded = blockSize - (privateSection.length() % blockSize);
		if (paddingNeeded == blockSize)
			paddingNeeded = 0;
		for (int i = 1; i <= paddingNeeded; i++) {
			privateSection.writeByte(i);
		}

		// Encrypt if passphrase provided
		byte[] privateSectionBytes;
		if (encrypted && salt != null) {
			byte[] derivedKey = deriveOpenSSHKey(passphrase, salt, OPENSSH_BCRYPT_ROUNDS);
			byte[] key = java.util.Arrays.copyOfRange(derivedKey, 0, OPENSSH_AES_KEY_SIZE);
			byte[] iv = java.util.Arrays.copyOfRange(derivedKey, OPENSSH_AES_KEY_SIZE,
					OPENSSH_AES_KEY_SIZE + OPENSSH_AES_IV_SIZE);
			try {
				privateSectionBytes = encryptAesCtr(privateSection.getBytes(), key, iv);
			} catch (IOException e) {
				throw new RuntimeException("Encryption failed", e);
			}
		} else {
			privateSectionBytes = privateSection.getBytes();
		}

		tw.writeString(privateSectionBytes, 0, privateSectionBytes.length);

		return formatOpenSSHKey(tw.getBytes());
	}

	/**
	 * Exports any supported key pair in OpenSSH format (unencrypted).
	 *
	 * @param privateKey The private key (RSA, DSA, EC, or Ed25519)
	 * @param publicKey  The public key
	 * @param comment    Optional comment
	 * @return The key in OpenSSH format, or null if the key type is not supported
	 * @throws InvalidKeyException if an EC key has an unsupported curve
	 */
	public static String exportOpenSSH(PrivateKey privateKey, PublicKey publicKey, String comment)
			throws InvalidKeyException {
		return exportOpenSSH(privateKey, publicKey, comment, null);
	}

	/**
	 * Exports any supported key pair in OpenSSH format.
	 *
	 * @param privateKey The private key (RSA, DSA, EC, or Ed25519)
	 * @param publicKey  The public key
	 * @param comment    Optional comment
	 * @param passphrase Optional passphrase for encryption. If null or empty, key
	 *                   is unencrypted.
	 * @return The key in OpenSSH format, or null if the key type is not supported
	 * @throws InvalidKeyException if an EC key has an unsupported curve
	 */
	public static String exportOpenSSH(PrivateKey privateKey, PublicKey publicKey, String comment, String passphrase)
			throws InvalidKeyException {
		if (privateKey instanceof RSAPrivateCrtKey && publicKey instanceof RSAPublicKey) {
			return exportOpenSSHRSA((RSAPrivateCrtKey) privateKey, (RSAPublicKey) publicKey, comment, passphrase);
		} else if (privateKey instanceof RSAPrivateKey && publicKey instanceof RSAPublicKey) {
			// Handle non-CRT RSA keys (e.g., from Conscrypt's OpenSSLRSAPrivateKey)
			try {
				RSAPrivateCrtKey crtKey = PEMEncoder.convertToRSAPrivateCrtKey((RSAPrivateKey) privateKey);
				return exportOpenSSHRSA(crtKey, (RSAPublicKey) publicKey, comment, passphrase);
			} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
				throw new InvalidKeyException("Failed to convert RSA key to CRT format", e);
			}
		} else if (privateKey instanceof DSAPrivateKey && publicKey instanceof DSAPublicKey) {
			return exportOpenSSHDSA((DSAPrivateKey) privateKey, (DSAPublicKey) publicKey, comment, passphrase);
		} else if (privateKey instanceof ECPrivateKey && publicKey instanceof ECPublicKey) {
			return exportOpenSSHEC((ECPrivateKey) privateKey, (ECPublicKey) publicKey, comment, passphrase);
		} else if (privateKey instanceof Ed25519PrivateKey && publicKey instanceof Ed25519PublicKey) {
			return exportOpenSSHEd25519((Ed25519PrivateKey) privateKey, (Ed25519PublicKey) publicKey, comment,
					passphrase);
		}
		throw new InvalidKeyException(
				"Unsupported key type: " + privateKey.getClass().getName() + " / " + publicKey.getClass().getName());
	}

	/**
	 * Formats raw key data into OpenSSH PEM format with proper line wrapping.
	 *
	 * @param data The raw key data
	 * @return The formatted PEM string
	 */
	private static String formatOpenSSHKey(byte[] data) {
		StringBuilder sb = new StringBuilder();
		sb.append(OPENSSH_PRIVATE_KEY_START);
		sb.append('\n');

		int i = sb.length();
		sb.append(Base64.encode(data));
		i += 70;
		while (i < sb.length()) {
			sb.insert(i, "\n");
			i += 71;
		}

		sb.append('\n');
		sb.append(OPENSSH_PRIVATE_KEY_END);
		sb.append('\n');

		return sb.toString();
	}

	/**
	 * Recovers a KeyPair from PKCS#8 encoded private key bytes.
	 * <p>
	 * This method can derive the public key from the private key for supported key
	 * types
	 * (RSA, DSA, EC, Ed25519). For Ed25519 keys, it uses Tink's Ed25519Sign to
	 * derive
	 * the public key from the private key seed.
	 *
	 * @param encoded The PKCS#8 encoded private key bytes
	 * @return The recovered KeyPair
	 * @throws NoSuchAlgorithmException if the key algorithm is not supported
	 * @throws InvalidKeySpecException  if the key specification is invalid
	 */
	public static KeyPair recoverKeyPair(byte[] encoded)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		String algo = getAlgorithmForOid(getOidFromPkcs8Encoded(encoded));

		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encoded);

		KeyFactory kf = KeyFactory.getInstance(algo);
		PrivateKey priv = kf.generatePrivate(privKeySpec);

		// Ed25519 requires special handling to derive the public key
		if (priv instanceof Ed25519PrivateKey) {
			byte[] seed = ((Ed25519PrivateKey) priv).getSeed();
			try {
				Ed25519Sign.KeyPair tinkKeyPair = Ed25519Sign.KeyPair.newKeyPairFromSeed(seed);
				Ed25519PublicKey publicKey = new Ed25519PublicKey(tinkKeyPair.getPublicKey());
				return new KeyPair(publicKey, priv);
			} catch (GeneralSecurityException e) {
				throw new InvalidKeySpecException("Failed to derive Ed25519 public key from seed", e);
			}
		}

		return new KeyPair(recoverPublicKey(kf, priv), priv);
	}

	/**
	 * Recovers the public key from a private key.
	 *
	 * @param kf   The KeyFactory for the key algorithm
	 * @param priv The private key
	 * @return The recovered public key
	 * @throws NoSuchAlgorithmException if the key type is not supported
	 * @throws InvalidKeySpecException  if the key specification is invalid
	 */
	public static PublicKey recoverPublicKey(KeyFactory kf, PrivateKey priv)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (priv instanceof RSAPrivateCrtKey) {
			RSAPrivateCrtKey rsaPriv = (RSAPrivateCrtKey) priv;
			return kf.generatePublic(
					new java.security.spec.RSAPublicKeySpec(
							rsaPriv.getModulus(),
							rsaPriv.getPublicExponent()));
		} else if (priv instanceof java.security.interfaces.RSAPrivateKey) {
			BigInteger publicExponent = getRSAPublicExponentFromPkcs8Encoded(priv.getEncoded());
			java.security.interfaces.RSAPrivateKey rsaPriv = (java.security.interfaces.RSAPrivateKey) priv;
			return kf.generatePublic(new java.security.spec.RSAPublicKeySpec(rsaPriv.getModulus(), publicExponent));
		} else if (priv instanceof DSAPrivateKey) {
			DSAPrivateKey dsaPriv = (DSAPrivateKey) priv;
			java.security.interfaces.DSAParams params = dsaPriv.getParams();

			// Calculate public key Y
			BigInteger y = params.getG().modPow(dsaPriv.getX(), params.getP());

			return kf.generatePublic(
					new java.security.spec.DSAPublicKeySpec(
							y, params.getP(), params.getQ(), params.getG()));
		} else if (priv instanceof ECPrivateKey) {
			ECPrivateKey ecPriv = (ECPrivateKey) priv;
			java.security.spec.ECParameterSpec params = ecPriv.getParams();

			// Calculate public key point using EC point multiplication
			// This requires a helper method to multiply the generator point by the private
			// scalar
			ECPoint generator = params.getGenerator();
			ECPoint w = multiplyECPoint(generator, ecPriv.getS(), params);

			return kf.generatePublic(new java.security.spec.ECPublicKeySpec(w, params));
		} else {
			throw new NoSuchAlgorithmException("Key type must be RSA, DSA, EC, or Ed25519");
		}
	}

	/**
	 * Gets the algorithm name from an OID.
	 *
	 * @param oid The OID string
	 * @return The algorithm name
	 * @throws NoSuchAlgorithmException if the OID is not recognized
	 */
	public static String getAlgorithmForOid(String oid) throws NoSuchAlgorithmException {
		if ("1.2.840.10045.2.1".equals(oid)) {
			return "EC";
		} else if ("1.2.840.113549.1.1.1".equals(oid)) {
			return "RSA";
		} else if ("1.2.840.10040.4.1".equals(oid)) {
			return "DSA";
		} else if ("1.3.101.112".equals(oid)) {
			return "Ed25519";
		} else {
			throw new NoSuchAlgorithmException("Unknown algorithm OID " + oid);
		}
	}

	/**
	 * Extracts the OID from a PKCS#8 encoded private key.
	 *
	 * @param encoded The PKCS#8 encoded key bytes
	 * @return The OID string
	 * @throws NoSuchAlgorithmException if the OID cannot be read
	 */
	public static String getOidFromPkcs8Encoded(byte[] encoded) throws NoSuchAlgorithmException {
		try {
			SimpleDERReader reader = new SimpleDERReader(encoded);
			reader.resetInput(reader.readSequenceAsByteArray());
			reader.readInt();
			reader.resetInput(reader.readSequenceAsByteArray());
			return reader.readOid();
		} catch (IOException e) {
			throw new NoSuchAlgorithmException("Could not read key", e);
		}
	}

	/**
	 * Extracts the RSA public exponent from a PKCS#8 encoded private key.
	 *
	 * @param encoded The PKCS#8 encoded key bytes
	 * @return The public exponent
	 * @throws InvalidKeySpecException if the key cannot be read
	 */
	public static BigInteger getRSAPublicExponentFromPkcs8Encoded(byte[] encoded) throws InvalidKeySpecException {
		try {
			SimpleDERReader reader = new SimpleDERReader(encoded);
			reader.resetInput(reader.readSequenceAsByteArray());
			if (!reader.readInt().equals(BigInteger.ZERO)) {
				throw new InvalidKeySpecException("PKCS#8 is not version 0");
			}

			reader.readSequenceAsByteArray(); // OID sequence
			reader.resetInput(reader.readOctetString()); // RSA key bytes
			reader.resetInput(reader.readSequenceAsByteArray()); // RSA key sequence

			if (!reader.readInt().equals(BigInteger.ZERO)) {
				throw new InvalidKeySpecException("RSA key is not version 0");
			}

			reader.readInt(); // modulus
			return reader.readInt(); // public exponent
		} catch (IOException e) {
			throw new InvalidKeySpecException("Could not read key", e);
		}
	}

	/**
	 * Multiplies an EC point by a scalar.
	 * Uses the double-and-add algorithm.
	 *
	 * @param point  The EC point (generator)
	 * @param scalar The scalar (private key)
	 * @param params The EC parameters
	 * @return The resulting EC point
	 */
	private static ECPoint multiplyECPoint(
			ECPoint point,
			BigInteger scalar,
			java.security.spec.ECParameterSpec params) {
		java.security.spec.EllipticCurve curve = params.getCurve();
		BigInteger p = ((java.security.spec.ECFieldFp) curve.getField()).getP();
		BigInteger a = curve.getA();

		ECPoint result = ECPoint.POINT_INFINITY;
		ECPoint addend = point;

		while (scalar.signum() > 0) {
			if (scalar.testBit(0)) {
				result = addECPoints(result, addend, p, a);
			}
			addend = doubleECPoint(addend, p, a);
			scalar = scalar.shiftRight(1);
		}

		return result;
	}

	/**
	 * Adds two EC points.
	 */
	private static ECPoint addECPoints(
			ECPoint p1,
			ECPoint p2,
			BigInteger p,
			BigInteger a) {
		if (p1.equals(ECPoint.POINT_INFINITY)) {
			return p2;
		}
		if (p2.equals(ECPoint.POINT_INFINITY)) {
			return p1;
		}

		BigInteger x1 = p1.getAffineX();
		BigInteger y1 = p1.getAffineY();
		BigInteger x2 = p2.getAffineX();
		BigInteger y2 = p2.getAffineY();

		if (x1.equals(x2)) {
			if (y1.equals(y2)) {
				return doubleECPoint(p1, p, a);
			} else {
				return ECPoint.POINT_INFINITY;
			}
		}

		BigInteger slope = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p)).mod(p);
		BigInteger x3 = slope.multiply(slope).subtract(x1).subtract(x2).mod(p);
		BigInteger y3 = slope.multiply(x1.subtract(x3)).subtract(y1).mod(p);

		return new ECPoint(x3, y3);
	}

	/**
	 * Doubles an EC point.
	 */
	private static ECPoint doubleECPoint(
			ECPoint point,
			BigInteger p,
			BigInteger a) {
		if (point.equals(ECPoint.POINT_INFINITY)) {
			return point;
		}

		BigInteger x = point.getAffineX();
		BigInteger y = point.getAffineY();

		if (y.signum() == 0) {
			return ECPoint.POINT_INFINITY;
		}

		BigInteger slope = x.multiply(x).multiply(BigInteger.valueOf(3)).add(a)
				.multiply(y.multiply(BigInteger.valueOf(2)).modInverse(p)).mod(p);
		BigInteger x3 = slope.multiply(slope).subtract(x.multiply(BigInteger.valueOf(2))).mod(p);
		BigInteger y3 = slope.multiply(x.subtract(x3)).subtract(y).mod(p);

		return new ECPoint(x3, y3);
	}
}

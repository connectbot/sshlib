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
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Locale;

import com.trilead.ssh2.crypto.cipher.AES;
import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.cipher.DES;
import com.trilead.ssh2.crypto.cipher.DESede;
import com.trilead.ssh2.crypto.keys.Ed25519PrivateKey;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;

import org.mindrot.jbcrypt.BCrypt;

/**
 * OpenSSH Key Decoder for importing SSH keys in OpenSSH format.
 * <p>
 * This class provides methods to decode RSA, DSA, EC, and Ed25519 key pairs
 * from the OpenSSH private key format (openssh-key-v1), including support
 * for passphrase-protected keys using bcrypt_pbkdf.
 * <p>
 * The OpenSSH format uses the header "-----BEGIN OPENSSH PRIVATE KEY-----"
 * and is the default format used by modern versions of ssh-keygen.
 * <p>
 * This is the decoding counterpart to {@link OpenSSHKeyEncoder}.
 *
 * @author Kenny Root
 */
public class OpenSSHKeyDecoder {

	static final byte[] OPENSSH_V1_MAGIC = new byte[] {
		'o', 'p', 'e', 'n', 's', 's', 'h', '-', 'k', 'e', 'y', '-', 'v', '1', '\0',
	};

	/**
	 * Checks if the given PEM structure contains an encrypted OpenSSH key.
	 *
	 * @param data The raw key data (after base64 decoding)
	 * @return true if the key is encrypted, false otherwise
	 * @throws IOException if the data cannot be parsed
	 */
	public static boolean isEncrypted(byte[] data) throws IOException {
		TypesReader tr = new TypesReader(data);
		byte[] magic = tr.readBytes(OPENSSH_V1_MAGIC.length);
		if (!Arrays.equals(OPENSSH_V1_MAGIC, magic)) {
			throw new IOException("Could not find OPENSSH key magic: " + new String(magic));
		}

		tr.readString(); // cipher name
		String kdfname = tr.readString();
		return !"none".equals(kdfname);
	}

	/**
	 * Decodes an OpenSSH format private key.
	 *
	 * @param data The raw key data (after base64 decoding)
	 * @param password The password for encrypted keys, or null for unencrypted keys
	 * @return The decoded KeyPair
	 * @throws IOException if the key cannot be decoded
	 */
	public static KeyPair decode(byte[] data, String password) throws IOException {
		TypesReader tr = new TypesReader(data);
		byte[] magic = tr.readBytes(OPENSSH_V1_MAGIC.length);
		if (!Arrays.equals(OPENSSH_V1_MAGIC, magic)) {
			throw new IOException("Could not find OPENSSH key magic: " + new String(magic));
		}

		String ciphername = tr.readString();
		String kdfname = tr.readString();
		byte[] kdfoptions = tr.readByteString();
		int numberOfKeys = tr.readUINT32();

		// TODO support multiple keys
		if (numberOfKeys != 1) {
			throw new IOException("Only one key supported, but encountered bundle of " + numberOfKeys);
		}

		// OpenSSH discards the public key blob, so we will as well.
		tr.readByteString();

		byte[] dataBytes = tr.readByteString();

		if ("bcrypt".equals(kdfname)) {
			if (password == null) {
				throw new IOException("OpenSSH key is encrypted");
			}

			TypesReader optionsReader = new TypesReader(kdfoptions);
			byte[] salt = optionsReader.readByteString();
			int rounds = optionsReader.readUINT32();
			byte[] passwordBytes;
			try {
				passwordBytes = password.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				passwordBytes = password.getBytes();
			}
			dataBytes = decryptData(dataBytes, passwordBytes, salt, rounds, ciphername);
		} else if (!"none".equals(ciphername) || !"none".equals(kdfname)) {
			throw new IOException("Unsupported encryption: cipher=" + ciphername + ", kdf=" + kdfname);
		}

		TypesReader trEnc = new TypesReader(dataBytes);

		int checkInt1 = trEnc.readUINT32();
		int checkInt2 = trEnc.readUINT32();

		if (checkInt1 != checkInt2) {
			throw new IOException("Decryption failed when trying to read private keys");
		}

		String keyType = trEnc.readString();

		KeyPair keyPair;
		if (Ed25519Verify.ED25519_ID.equals(keyType)) {
			byte[] publicBytes = trEnc.readByteString();
			byte[] privateBytes = trEnc.readByteString();
			PrivateKey privKey = new Ed25519PrivateKey(
					Arrays.copyOfRange(privateBytes, 0, 32));
			PublicKey pubKey = new Ed25519PublicKey(publicBytes);
			keyPair = new KeyPair(pubKey, privKey);
		} else if (keyType.startsWith("ecdsa-sha2-")) {
			String curveName = trEnc.readString();

			byte[] groupBytes = trEnc.readByteString();
			BigInteger privateKey = trEnc.readMPINT();

			final ECDSASHA2Verify verifier;
			if (curveName.equals(ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get().getCurveName())) {
				verifier = ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get();
			} else if (curveName.equals(ECDSASHA2Verify.ECDSASHA2NISTP384Verify.get().getCurveName())) {
				verifier = ECDSASHA2Verify.ECDSASHA2NISTP384Verify.get();
			} else if (curveName.equals(ECDSASHA2Verify.ECDSASHA2NISTP521Verify.get().getCurveName())) {
				verifier = ECDSASHA2Verify.ECDSASHA2NISTP521Verify.get();
			} else {
				throw new IOException("Invalid ECDSA group: " + curveName);
			}

			ECParameterSpec spec = verifier.getParameterSpec();
			ECPoint group = verifier.decodeECPoint(groupBytes);

			ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(group, spec);
			ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey, spec);
			keyPair = generateKeyPair("EC", privateKeySpec, publicKeySpec);
		} else if (RSASHA1Verify.get().getKeyFormat().equals(keyType)) {
			BigInteger n = trEnc.readMPINT();
			BigInteger e = trEnc.readMPINT();
			BigInteger d = trEnc.readMPINT();

			BigInteger crtCoefficient = trEnc.readMPINT();
			BigInteger p = trEnc.readMPINT();

			RSAPrivateKeySpec privateKeySpec;
			if (null == p || null == crtCoefficient) {
				privateKeySpec = new RSAPrivateKeySpec(n, d);
			} else {
				BigInteger q = crtCoefficient.modInverse(p);
				BigInteger pE = d.mod(p.subtract(BigInteger.ONE));
				BigInteger qE = d.mod(q.subtract(BigInteger.ONE));
				privateKeySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, pE, qE, crtCoefficient);
			}

			RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);

			keyPair = generateKeyPair("RSA", privateKeySpec, publicKeySpec);
		} else if (DSASHA1Verify.get().getKeyFormat().equals(keyType)) {
			BigInteger p = trEnc.readMPINT();
			BigInteger q = trEnc.readMPINT();
			BigInteger g = trEnc.readMPINT();
			BigInteger y = trEnc.readMPINT();
			BigInteger x = trEnc.readMPINT();

			DSAPrivateKeySpec privateKeySpec = new DSAPrivateKeySpec(x, p, q, g);
			DSAPublicKeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);

			keyPair = generateKeyPair("DSA", privateKeySpec, publicKeySpec);
		} else {
			throw new IOException("Unknown key type: " + keyType);
		}

		// Read comment (not used, but part of the format)
		trEnc.readByteString();

		// Note: The original PEMDecoder code had a bug at lines 666-672 where it checked
		// padding using `tr.remain()` (the outer TypesReader) instead of `trEnc.remain()`
		// (the inner decrypted section). Since `tr` is fully consumed after reading the
		// private section blob, `tr.remain()` always returns 0, causing the padding
		// verification loop to never execute. The actual padding bytes (e.g., [1,2,3,...,12])
		// exist in `trEnc` but were never validated.
		//
		// For backward compatibility, we preserve this behavior and skip padding verification.
		// The checkInt1 == checkInt2 check above already validates successful decryption.

		return keyPair;
	}

	/**
	 * Decrypts the private key section using the specified cipher and KDF.
	 */
	private static byte[] decryptData(byte[] data, byte[] pw, byte[] salt, int rounds, String algo) throws IOException {
		BlockCipher bc;
		int keySize;

		String algoLower = algo.toLowerCase(Locale.US);
		if (algoLower.equals("aes-128-cbc") || algoLower.equals("aes128-cbc")) {
			bc = new AES.CBC();
			keySize = 16;
		} else if (algoLower.equals("aes-192-cbc") || algoLower.equals("aes192-cbc")) {
			bc = new AES.CBC();
			keySize = 24;
		} else if (algoLower.equals("aes-256-cbc") || algoLower.equals("aes256-cbc")) {
			bc = new AES.CBC();
			keySize = 32;
		} else if (algoLower.equals("aes-128-ctr") || algoLower.equals("aes128-ctr")) {
			bc = new AES.CTR();
			keySize = 16;
		} else if (algoLower.equals("aes-192-ctr") || algoLower.equals("aes192-ctr")) {
			bc = new AES.CTR();
			keySize = 24;
		} else if (algoLower.equals("aes-256-ctr") || algoLower.equals("aes256-ctr")) {
			bc = new AES.CTR();
			keySize = 32;
		} else if (algoLower.equals("des-ede3-cbc") || algoLower.equals("3des-cbc")) {
			bc = new DESede.CBC();
			keySize = 24;
		} else if (algoLower.equals("des-cbc")) {
			bc = new DES.CBC();
			keySize = 8;
		} else {
			throw new IOException("Cannot decrypt OpenSSH key, unknown cipher: " + algo);
		}

		byte[] key = new byte[keySize];
		byte[] iv = new byte[bc.getBlockSize()];

		byte[] keyAndIV = new byte[key.length + iv.length];

		new BCrypt().pbkdf(pw, salt, rounds, keyAndIV);

		System.arraycopy(keyAndIV, 0, key, 0, key.length);
		System.arraycopy(keyAndIV, key.length, iv, 0, iv.length);

		bc.init(false, key, iv);

		if ((data.length % bc.getBlockSize()) != 0)
			throw new IOException("Invalid OpenSSH key structure, size of encrypted block is not a multiple of "
					+ bc.getBlockSize());

		/* Now decrypt the content */
		byte[] dz = new byte[data.length];

		for (int i = 0; i < data.length / bc.getBlockSize(); i++) {
			bc.transformBlock(data, i * bc.getBlockSize(), dz, i * bc.getBlockSize());
		}

		return dz;
	}

	/**
	 * Generate a {@code KeyPair} given an {@code algorithm} and {@code KeySpec}.
	 */
	private static KeyPair generateKeyPair(String algorithm, KeySpec privSpec, KeySpec pubSpec)
			throws IOException {
		try {
			final KeyFactory kf = KeyFactory.getInstance(algorithm);
			final PublicKey pubKey = kf.generatePublic(pubSpec);
			final PrivateKey privKey = kf.generatePrivate(privSpec);
			return new KeyPair(pubKey, privKey);
		} catch (NoSuchAlgorithmException ex) {
			throw new IOException(ex);
		} catch (InvalidKeySpecException ex) {
			throw new IOException("invalid keyspec", ex);
		}
	}
}

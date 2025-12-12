package com.trilead.ssh2.crypto;

import java.io.IOException;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

import org.mindrot.jbcrypt.BCrypt;

import com.trilead.ssh2.crypto.cipher.AES;
import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.cipher.DES;
import com.trilead.ssh2.crypto.cipher.DESede;

/**
 * Common decryption utilities for SSH key decoders.
 *
 * @author Kenny Root
 */
class CommonDecoder {
	static byte[] decryptData(byte[] data, byte[] pw, byte[] salt, int rounds, String algo) throws IOException {
		BlockCipher bc;
		int keySize;

		String algoLower = algo.toLowerCase(Locale.US);
		if (algoLower.equals("des-ede3-cbc")) {
			bc = new DESede.CBC();
			keySize = 24;
		} else if (algoLower.equals("des-cbc")) {
			bc = new DES.CBC();
			keySize = 8;
		} else if (algoLower.equals("aes-128-cbc") || algoLower.equals("aes128-cbc")) {
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
		} else {
			throw new IOException("Cannot decrypt, unknown cipher " + algo);
		}

		if (rounds == -1) {
			bc.init(false, generateKeyFromPasswordSaltWithMD5(pw, salt, keySize), salt);
		} else {
			byte[] key = new byte[keySize];
			byte[] iv = new byte[bc.getBlockSize()];

			byte[] keyAndIV = new byte[key.length + iv.length];

			new BCrypt().pbkdf(pw, salt, rounds, keyAndIV);

			System.arraycopy(keyAndIV, 0, key, 0, key.length);
			System.arraycopy(keyAndIV, key.length, iv, 0, iv.length);

			bc.init(false, key, iv);
		}

		if ((data.length % bc.getBlockSize()) != 0)
			throw new IOException("Size of encrypted block is not a multiple of "
					+ bc.getBlockSize());

		/* Now decrypt the content */
		byte[] dz = new byte[data.length];

		for (int i = 0; i < data.length / bc.getBlockSize(); i++) {
			bc.transformBlock(data, i * bc.getBlockSize(), dz, i * bc.getBlockSize());
		}

		if (rounds == -1) {
			/* Now check and remove RFC 1423/PKCS #7 padding */
			return removePadding(dz, bc.getBlockSize());
		} else {
			/* New style is to check the padding after reading the comment. */
			return dz;
		}
	}

	private static byte[] removePadding(byte[] buff, int blockSize) throws IOException {
		/* Removes RFC 1423/PKCS #7 padding */

		int rfc_1423_padding = buff[buff.length - 1] & 0xff;

		if ((rfc_1423_padding < 1) || (rfc_1423_padding > blockSize))
			throw new IOException("Decrypted block has wrong padding, did you specify the correct password?");

		for (int i = 2; i <= rfc_1423_padding; i++) {
			if (buff[buff.length - i] != rfc_1423_padding)
				throw new IOException("Decrypted block has wrong padding, did you specify the correct password?");
		}

		byte[] tmp = new byte[buff.length - rfc_1423_padding];
		System.arraycopy(buff, 0, tmp, 0, buff.length - rfc_1423_padding);
		return tmp;
	}

	private static byte[] generateKeyFromPasswordSaltWithMD5(byte[] password, byte[] salt, int keyLen)
			throws IOException {
		if (salt.length < 8)
			throw new IllegalArgumentException("Salt needs to be at least 8 bytes for key generation.");

		MessageDigest md5;
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("JVM does not support MD5", e);
		}

		byte[] key = new byte[keyLen];
		byte[] tmp = new byte[md5.getDigestLength()];

		while (true) {
			md5.update(password, 0, password.length);
			md5.update(salt, 0, 8); // ARGH we only use the first 8 bytes of the
			// salt in this step.
			// This took me two hours until I got AES-xxx running.

			int copy = (keyLen < tmp.length) ? keyLen : tmp.length;

			try {
				md5.digest(tmp, 0, tmp.length);
			} catch (DigestException e) {
				throw new IOException("could not digest password", e);
			}

			System.arraycopy(tmp, 0, key, key.length - keyLen, copy);

			keyLen -= copy;

			if (keyLen == 0)
				return key;

			md5.update(tmp, 0, tmp.length);
		}
	}
}

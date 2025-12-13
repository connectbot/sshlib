package com.trilead.ssh2.crypto.fingerprint;

import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.crypto.PublicKeyUtils;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Utilities for creating SSH key fingerprints in various formats.
 * Implements OpenSSH-compatible fingerprinting algorithms including SHA-256,
 * MD5, Bubble-Babble, and ASCII art randomart visualization.
 *
 * @author Kenny Root
 */
public class KeyFingerprint {

	private static final char[] VOWELS = {'a', 'e', 'i', 'o', 'u', 'y'};
	private static final char[] CONSONANTS = {'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
			'n', 'p', 'r', 's', 't', 'v', 'z', 'x'};

	private static final int FLDBASE = 8;
	private static final int FLDSIZE_Y = FLDBASE + 1;
	private static final int FLDSIZE_X = (FLDBASE * 2) + 1;
	private static final String AUGMENTATION_STRING = " .o+=*BOX@%&#/^SE";

	/**
	 * Create SHA-256 fingerprint in Base64 format (OpenSSH default).
	 *
	 * @param publicKeyBlob SSH wire format public key blob
	 * @return fingerprint string (e.g., "SHA256:kKbdmK+Vqeu/XRnlPNOMuAgG7cIeii3bYsZTY6tY1xM")
	 */
	public static String createSHA256Fingerprint(byte[] publicKeyBlob) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hash = md.digest(publicKeyBlob);
			String base64 = new String(Base64.encode(hash));
			base64 = base64.replace("=", "");
			return "SHA256:" + base64;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-256 not available", e);
		}
	}

	/**
	 * Create SHA-256 fingerprint from PublicKey.
	 *
	 * @param publicKey the public key
	 * @return fingerprint string
	 * @throws IOException if encoding fails
	 * @throws InvalidKeyException if key type is not supported
	 */
	public static String createSHA256Fingerprint(PublicKey publicKey)
			throws IOException, InvalidKeyException {
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(publicKey);
		return createSHA256Fingerprint(blob);
	}

	/**
	 * Create SHA-256 fingerprint in hex format.
	 *
	 * @param publicKeyBlob SSH wire format public key blob
	 * @return fingerprint string (e.g., "SHA256:90:a6:dd:98:af:95...")
	 */
	public static String createSHA256FingerprintHex(byte[] publicKeyBlob) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hash = md.digest(publicKeyBlob);
			return "SHA256:" + toHexFingerprint(hash);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-256 not available", e);
		}
	}

	/**
	 * Create SHA-256 fingerprint in hex format from PublicKey.
	 *
	 * @param publicKey the public key
	 * @return fingerprint string
	 * @throws IOException if encoding fails
	 * @throws InvalidKeyException if key type is not supported
	 */
	public static String createSHA256FingerprintHex(PublicKey publicKey)
			throws IOException, InvalidKeyException {
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(publicKey);
		return createSHA256FingerprintHex(blob);
	}

	/**
	 * Create MD5 fingerprint (legacy format for compatibility).
	 *
	 * @param publicKeyBlob SSH wire format public key blob
	 * @return fingerprint string (e.g., "7b:7f:ef:47:43:38:05:39...")
	 */
	public static String createMD5Fingerprint(byte[] publicKeyBlob) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] hash = md.digest(publicKeyBlob);
			return toHexFingerprint(hash);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("MD5 not available", e);
		}
	}

	/**
	 * Create MD5 fingerprint from PublicKey.
	 *
	 * @param publicKey the public key
	 * @return fingerprint string
	 * @throws IOException if encoding fails
	 * @throws InvalidKeyException if key type is not supported
	 */
	public static String createMD5Fingerprint(PublicKey publicKey)
			throws IOException, InvalidKeyException {
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(publicKey);
		return createMD5Fingerprint(blob);
	}

	/**
	 * Create Bubble-Babble fingerprint (phonetic encoding).
	 *
	 * @param publicKeyBlob SSH wire format public key blob
	 * @return fingerprint string (e.g., "xitiz-ritah-gykez...")
	 */
	public static String createBubblebabbleFingerprint(byte[] publicKeyBlob) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			byte[] hash = md.digest(publicKeyBlob);
			return toBubblebabble(hash);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-1 not available", e);
		}
	}

	/**
	 * Create Bubble-Babble fingerprint from PublicKey.
	 *
	 * @param publicKey the public key
	 * @return fingerprint string
	 * @throws IOException if encoding fails
	 * @throws InvalidKeyException if key type is not supported
	 */
	public static String createBubblebabbleFingerprint(PublicKey publicKey)
			throws IOException, InvalidKeyException {
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(publicKey);
		return createBubblebabbleFingerprint(blob);
	}

	/**
	 * Create randomart visualization (ASCII art).
	 *
	 * @param publicKeyBlob SSH wire format public key blob
	 * @param keyType key type name (e.g., "RSA", "ED25519")
	 * @param keySize key size in bits
	 * @return randomart string (multi-line ASCII art)
	 */
	public static String createRandomArt(byte[] publicKeyBlob, String keyType, int keySize) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hash = md.digest(publicKeyBlob);
			return toRandomArt(hash, keyType, keySize);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-256 not available", e);
		}
	}

	/**
	 * Create randomart visualization from PublicKey.
	 *
	 * @param publicKey the public key
	 * @return randomart string
	 * @throws IOException if encoding fails
	 * @throws InvalidKeyException if key type is not supported
	 */
	public static String createRandomArt(PublicKey publicKey)
			throws IOException, InvalidKeyException {
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(publicKey);

		String keyType;
		int keySize;

		if (publicKey instanceof RSAPublicKey) {
			RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
			keyType = "RSA";
			keySize = rsaKey.getModulus().bitLength();
		} else if (publicKey instanceof DSAPublicKey) {
			DSAPublicKey dsaKey = (DSAPublicKey) publicKey;
			keyType = "DSA";
			keySize = dsaKey.getParams().getP().bitLength();
		} else if (publicKey instanceof ECPublicKey) {
			ECPublicKey ecKey = (ECPublicKey) publicKey;
			keyType = "ECDSA";
			keySize = ecKey.getParams().getCurve().getField().getFieldSize();
		} else if (publicKey instanceof Ed25519PublicKey) {
			keyType = "ED25519";
			keySize = 256;
		} else {
			throw new InvalidKeyException("Unknown key type: " + publicKey.getClass().getName());
		}

		return createRandomArt(blob, keyType, keySize);
	}

	private static String toHexFingerprint(byte[] hash) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < hash.length; i++) {
			if (i > 0) {
				sb.append(':');
			}
			int b = hash[i] & 0xff;
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	private static String toBubblebabble(byte[] hash) {
		StringBuilder sb = new StringBuilder();
		int seed = 1;
		int rounds = (hash.length / 2) + 1;

		sb.append('x');

		for (int i = 0; i < rounds; i++) {
			if (i < hash.length / 2) {
				int byte1 = hash[2 * i] & 0xff;
				int byte2 = hash[2 * i + 1] & 0xff;

				int idx0 = (((byte1 >> 6) & 3) + seed) % 6;
				int idx1 = (byte1 >> 2) & 15;
				int idx2 = ((byte1 & 3) + (seed / 6)) % 6;
				int idx3 = (byte2 >> 4) & 15;
				int idx4 = byte2 & 15;

				sb.append(VOWELS[idx0]);
				sb.append(CONSONANTS[idx1]);
				sb.append(VOWELS[idx2]);
				sb.append(CONSONANTS[idx3]);
				sb.append('-');
				sb.append(CONSONANTS[idx4]);

				seed = ((seed * 5) + (byte1 * 7) + byte2) % 36;
			} else {
				int idx0 = seed % 6;
				int idx1 = 16;
				int idx2 = seed / 6;

				sb.append(VOWELS[idx0]);
				sb.append(CONSONANTS[idx1]);
				sb.append(VOWELS[idx2]);
			}
		}

		sb.append('x');
		return sb.toString();
	}

	private static String toRandomArt(byte[] hash, String keyType, int keySize) {
		int[][] field = new int[FLDSIZE_X][FLDSIZE_Y];

		int x = FLDSIZE_X / 2;
		int y = FLDSIZE_Y / 2;

		for (byte b : hash) {
			int input = b & 0xff;
			for (int i = 0; i < 4; i++) {
				x += ((input & 0x1) != 0) ? 1 : -1;
				y += ((input & 0x2) != 0) ? 1 : -1;

				x = Math.max(x, 0);
				y = Math.max(y, 0);
				x = Math.min(x, FLDSIZE_X - 1);
				y = Math.min(y, FLDSIZE_Y - 1);

				if (field[x][y] < AUGMENTATION_STRING.length() - 2) {
					field[x][y]++;
				}

				input >>= 2;
			}
		}

		field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = AUGMENTATION_STRING.length() - 2;
		field[x][y] = AUGMENTATION_STRING.length() - 1;

		StringBuilder sb = new StringBuilder();
		String header = String.format("[%s %d]", keyType, keySize);
		int headerPadding = (FLDSIZE_X - header.length()) / 2;
		sb.append('+');
		for (int i = 0; i < headerPadding; i++) {
			sb.append('-');
		}
		sb.append(header);
		for (int i = 0; i < FLDSIZE_X - headerPadding - header.length(); i++) {
			sb.append('-');
		}
		sb.append('+');
		sb.append('\n');

		for (int j = 0; j < FLDSIZE_Y; j++) {
			sb.append('|');
			for (int i = 0; i < FLDSIZE_X; i++) {
				sb.append(AUGMENTATION_STRING.charAt(field[i][j]));
			}
			sb.append('|');
			if (j < FLDSIZE_Y - 1) {
				sb.append('\n');
			}
		}

		sb.append('\n');
		sb.append('+');
		for (int i = 0; i < (FLDSIZE_X - 8) / 2; i++) {
			sb.append('-');
		}
		sb.append("[SHA256]");
		for (int i = 0; i < FLDSIZE_X - ((FLDSIZE_X - 8) / 2) - 8; i++) {
			sb.append('-');
		}
		sb.append('+');

		return sb.toString();
	}
}

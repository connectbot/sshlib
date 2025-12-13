package com.trilead.ssh2.crypto;

import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;
import com.trilead.ssh2.signature.SSHSignature;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Utilities for working with SSH public keys.
 *
 * @author Kenny Root
 */
public class PublicKeyUtils {

	private static final String OPENSSH_PRIVATE_KEY_START = "-----BEGIN OPENSSH PRIVATE KEY-----";
	private static final String OPENSSH_PRIVATE_KEY_END = "-----END OPENSSH PRIVATE KEY-----";
	private static final String OPENSSH_KEY_V1_MAGIC = "openssh-key-v1\0";

	/**
	 * Convert a public key to OpenSSH authorized_keys format.
	 *
	 * @param publicKey the public key to convert
	 * @param comment   comment to append (e.g., "user@host")
	 * @return OpenSSH format string (e.g., "ssh-rsa AAAA... comment")
	 * @throws IOException         if encoding fails
	 * @throws InvalidKeyException if key type is not supported
	 */
	public static String toAuthorizedKeysFormat(PublicKey publicKey, String comment)
			throws IOException, InvalidKeyException {
		if (comment == null) {
			comment = "";
		}

		if (publicKey instanceof RSAPublicKey) {
			RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
			byte[] encoded = RSASHA1Verify.get().encodePublicKey(rsaKey);
			String data = "ssh-rsa " + new String(Base64.encode(encoded));
			return comment.isEmpty() ? data : data + " " + comment;
		} else if (publicKey instanceof DSAPublicKey) {
			DSAPublicKey dsaKey = (DSAPublicKey) publicKey;
			byte[] encoded = DSASHA1Verify.get().encodePublicKey(dsaKey);
			String data = "ssh-dss " + new String(Base64.encode(encoded));
			return comment.isEmpty() ? data : data + " " + comment;
		} else if (publicKey instanceof ECPublicKey) {
			ECPublicKey ecKey = (ECPublicKey) publicKey;
			String keyType = ECDSASHA2Verify.getSshKeyType(ecKey);
			SSHSignature verifier = ECDSASHA2Verify.getVerifierForKey(ecKey);
			byte[] encoded = verifier.encodePublicKey(ecKey);
			String data = keyType + " " + new String(Base64.encode(encoded));
			return comment.isEmpty() ? data : data + " " + comment;
		} else if (publicKey instanceof Ed25519PublicKey) {
			Ed25519PublicKey ed25519Key = (Ed25519PublicKey) publicKey;
			byte[] encoded = Ed25519Verify.get().encodePublicKey(ed25519Key);
			String data = Ed25519Verify.ED25519_ID + " " + new String(Base64.encode(encoded));
			return comment.isEmpty() ? data : data + " " + comment;
		} else {
			throw new InvalidKeyException("Unknown key type: " + publicKey.getClass().getName());
		}
	}

	/**
	 * Extract SSH wire format public key blob from a PublicKey.
	 *
	 * @param publicKey the public key
	 * @return SSH wire format blob
	 * @throws IOException         if encoding fails
	 * @throws InvalidKeyException if key type is not supported
	 */
	public static byte[] extractPublicKeyBlob(PublicKey publicKey)
			throws IOException, InvalidKeyException {
		if (publicKey instanceof RSAPublicKey) {
			return RSASHA1Verify.get().encodePublicKey((RSAPublicKey) publicKey);
		} else if (publicKey instanceof DSAPublicKey) {
			return DSASHA1Verify.get().encodePublicKey((DSAPublicKey) publicKey);
		} else if (publicKey instanceof ECPublicKey) {
			ECPublicKey ecKey = (ECPublicKey) publicKey;
			SSHSignature verifier = ECDSASHA2Verify.getVerifierForKey(ecKey);
			return verifier.encodePublicKey(ecKey);
		} else if (publicKey instanceof Ed25519PublicKey) {
			return Ed25519Verify.get().encodePublicKey((Ed25519PublicKey) publicKey);
		} else {
			throw new InvalidKeyException("Unknown key type: " + publicKey.getClass().getName());
		}
	}

	/**
	 * Detect the key type from OpenSSH format private key data without requiring password.
	 * This reads the unencrypted public key section of the OpenSSH format.
	 *
	 * @param opensshKeyData the OpenSSH format private key data
	 * @return key type ("RSA", "DSA", "EC", "Ed25519") or null if not detectable
	 */
	public static String detectKeyType(byte[] opensshKeyData) {
		try {
			String keyString = new String(opensshKeyData, StandardCharsets.UTF_8);
			return detectKeyType(keyString);
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * Detect the key type from OpenSSH format private key string without requiring password.
	 * This reads the unencrypted public key section of the OpenSSH format.
	 *
	 * @param keyString the OpenSSH format private key as string
	 * @return key type ("RSA", "DSA", "EC", "Ed25519") or null if not detectable
	 */
	public static String detectKeyType(String keyString) {
		try {
			if (!keyString.contains(OPENSSH_PRIVATE_KEY_START)) {
				return null;
			}

			int startIdx = keyString.indexOf(OPENSSH_PRIVATE_KEY_START) + OPENSSH_PRIVATE_KEY_START.length();
			int endIdx = keyString.indexOf(OPENSSH_PRIVATE_KEY_END);
			if (startIdx < 0 || endIdx < 0 || startIdx >= endIdx) {
				return null;
			}

			String base64Content = keyString.substring(startIdx, endIdx)
					.replace("\n", "")
					.replace("\r", "")
					.trim();

			byte[] decoded = Base64.decode(base64Content.toCharArray());
			ByteBuffer buffer = ByteBuffer.wrap(decoded);

			byte[] magic = new byte[15];
			buffer.get(magic);
			if (!new String(magic, StandardCharsets.US_ASCII).equals(OPENSSH_KEY_V1_MAGIC)) {
				return null;
			}

			int cipherLen = buffer.getInt();
			buffer.position(buffer.position() + cipherLen);

			int kdfLen = buffer.getInt();
			buffer.position(buffer.position() + kdfLen);

			int kdfOptionsLen = buffer.getInt();
			buffer.position(buffer.position() + kdfOptionsLen);

			buffer.getInt();

			@SuppressWarnings("unused")
			int pubKeyBlobLen = buffer.getInt();

			int keyTypeLen = buffer.getInt();
			byte[] keyTypeBytes = new byte[keyTypeLen];
			buffer.get(keyTypeBytes);
			String sshKeyType = new String(keyTypeBytes, StandardCharsets.UTF_8);

			if (sshKeyType.equals("ssh-rsa")) {
				return "RSA";
			} else if (sshKeyType.equals("ssh-dss")) {
				return "DSA";
			} else if (sshKeyType.equals("ssh-ed25519")) {
				return "Ed25519";
			} else if (sshKeyType.startsWith("ecdsa-sha2-")) {
				return "EC";
			} else {
				return null;
			}
		} catch (Exception e) {
			return null;
		}
	}
}

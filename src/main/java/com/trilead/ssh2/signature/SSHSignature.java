package com.trilead.ssh2.signature;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Interface for SSH signature algorithms.
 * <p>
 * Defines operations for encoding/decoding SSH public keys and
 * generating/verifying SSH-format signatures.
 *
 * @see ECDSASHA2Verify
 * @see RSASHA256Verify
 * @see RSASHA512Verify
 */
public interface SSHSignature {
	/**
	 * Returns the supported signature formats.
	 * @return the supported signature formats
	 */
	String getKeyFormat();

	/**
	 * Decode from SSH specification key to Java public key.
	 * @param encoded the encoded key
	 * @return the decoded public key
	 * @throws IOException on error
	 */
	PublicKey decodePublicKey(byte[] encoded) throws IOException;

	/**
	 * Encode from Java public key to SSH specification.
	 * @param publicKey the public key to encode
	 * @return the encoded public key
	 * @throws IOException on error
	 */
	byte[] encodePublicKey(PublicKey publicKey) throws IOException;

	/**
	 * Verifies a SSH-format signature for a given key.
	 * @param message the message
	 * @param signature the signature
	 * @param publicKey the public key
	 * @return true if the signature is valid
	 * @throws IOException on error
	 */
	boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey) throws IOException;

	/**
	 * Generate an SSH-format signature for the message and private key.
	 * @param message the message
	 * @param privateKey the private key
	 * @param secureRandom the secure random source
	 * @return the generated signature
	 * @throws IOException on error
	 */
	byte[] generateSignature(byte[] message, PrivateKey privateKey, SecureRandom secureRandom) throws IOException;
}

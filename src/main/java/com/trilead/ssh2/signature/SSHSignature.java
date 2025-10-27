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
	/** Returns the supported signature formats. */
	String getKeyFormat();

	/** Decode from SSH specification key to Java public key. */
	PublicKey decodePublicKey(byte[] encoded) throws IOException;

	/** Encode from Java public key to SSH specification. */
	byte[] encodePublicKey(PublicKey publicKey) throws IOException;

	/** Verifies a SSH-format signature for a given key. */
	boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey) throws IOException;

	/** Generate an SSH-format signature for the message and private key. */
	byte[] generateSignature(byte[] message, PrivateKey privateKey, SecureRandom secureRandom) throws IOException;
}

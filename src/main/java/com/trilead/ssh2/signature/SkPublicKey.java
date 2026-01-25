
package com.trilead.ssh2.signature;

import java.security.PublicKey;

/**
 * Interface for FIDO2 Security Key (SK) public keys used in SSH authentication.
 *
 * SK keys are hardware-backed keys where the private key never leaves the device.
 * The signature format includes additional fields (flags, counter) beyond the
 * raw cryptographic signature.
 *
 * Implementations should provide:
 * - sk-ssh-ed25519@openssh.com for Ed25519-based SK keys
 * - sk-ecdsa-sha2-nistp256@openssh.com for ECDSA P-256 SK keys
 */
public interface SkPublicKey extends PublicKey {

	/**
	 * Get the SSH key type identifier.
	 *
	 * @return The key type string, e.g., "sk-ssh-ed25519@openssh.com" or
	 *         "sk-ecdsa-sha2-nistp256@openssh.com"
	 */
	String getSshKeyType();

	/**
	 * Get the application ID (relying party ID) for this key.
	 * Typically "ssh:" for SSH authentication.
	 *
	 * @return The application ID string
	 */
	String getApplication();

	/**
	 * Get the underlying key data (without the key type prefix).
	 * For Ed25519, this is the 32-byte public key.
	 * For ECDSA, this is the uncompressed EC point.
	 *
	 * @return The raw key bytes
	 */
	byte[] getKeyData();
}

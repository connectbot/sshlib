package com.trilead.ssh2.crypto.cipher;

/**
 * Authenticated Encryption with Associated Data (AEAD) cipher interface.
 *
 * AEAD ciphers combine encryption and authentication in a single operation,
 * unlike traditional SSH ciphers that use separate cipher and MAC algorithms.
 *
 * This interface supports the OpenSSH ChaCha20-Poly1305 AEAD cipher
 * (chacha20-poly1305@openssh.com) as specified in draft-ietf-sshm-chacha20-poly1305-02.
 *
 * @author Kenny Root
 */
public interface AeadCipher
{
	/**
	 * Initialize the AEAD cipher for encryption or decryption.
	 *
	 * @param forEncryption true for encryption, false for decryption
	 * @param key key material (size depends on cipher, e.g., 64 bytes for ChaCha20-Poly1305)
	 * @throws IllegalArgumentException if key size is invalid
	 */
	void init(boolean forEncryption, byte[] key) throws IllegalArgumentException;

	/**
	 * Get the key size in bytes required by this cipher.
	 *
	 * @return key size in bytes
	 */
	int getKeySize();

	/**
	 * Get the authentication tag size in bytes (e.g., 16 for Poly1305).
	 *
	 * @return tag size in bytes
	 */
	int getTagSize();

	/**
	 * Encrypt the 4-byte packet length field.
	 *
	 * @param seqNum SSH packet sequence number
	 * @param plainLength 4-byte packet length (big-endian)
	 * @param dest destination buffer for encrypted length
	 * @param destOff offset in destination buffer
	 */
	void encryptPacketLength(int seqNum, byte[] plainLength, byte[] dest, int destOff);

	/**
	 * Decrypt the 4-byte packet length field.
	 *
	 * @param seqNum SSH packet sequence number
	 * @param encryptedLength 4-byte encrypted length
	 * @param dest destination buffer for plaintext length
	 * @param destOff offset in destination buffer
	 */
	void decryptPacketLength(int seqNum, byte[] encryptedLength, byte[] dest, int destOff);

	/**
	 * Encrypt and authenticate the packet payload.
	 *
	 * @param seqNum SSH packet sequence number
	 * @param plaintext plaintext payload (padding_length + payload + padding)
	 * @param ciphertext output buffer for ciphertext (same size as plaintext)
	 * @param tag output buffer for authentication tag
	 * @param encryptedLength the encrypted 4-byte length field (for AAD)
	 */
	void seal(int seqNum, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] encryptedLength);

	/**
	 * Verify and decrypt the packet payload.
	 *
	 * @param seqNum SSH packet sequence number
	 * @param ciphertext encrypted payload
	 * @param tag authentication tag to verify
	 * @param plaintext output buffer for plaintext
	 * @param encryptedLength the encrypted 4-byte length field (for AAD)
	 * @return true if tag verification succeeded, false otherwise
	 */
	boolean open(int seqNum, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] encryptedLength);
}

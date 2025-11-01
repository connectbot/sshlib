package com.trilead.ssh2.crypto.cipher;

import java.io.IOException;

/**
 * Authenticated Encryption with Associated Data (AEAD) cipher interface.
 *
 * AEAD ciphers combine encryption and authentication in a single operation,
 * unlike traditional SSH ciphers that use separate cipher and MAC algorithms.
 *
 * @author Kenny Root
 */
public interface AeadCipher
{
	/**
	 * Initialize the AEAD cipher for encryption or decryption.
	 *
	 * @param forEncryption true for encryption, false for decryption
	 * @param key encryption key material (size depends on cipher)
	 * @param iv initial IV material (size depends on cipher, may be unused for some AEAD ciphers)
	 * @throws IllegalArgumentException if key or IV size is invalid
	 */
	void init(boolean forEncryption, byte[] key, byte[] iv) throws IllegalArgumentException;

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
	 * Gets the block size of the cipher.
	 *
	 * @return block size in bytes
	 */
	int getBlockSize();

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
	 * @throws IOException on decryption errors
	 */
	boolean open(int seqNum, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] encryptedLength)
			throws IOException;
}

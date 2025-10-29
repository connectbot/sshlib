package com.trilead.ssh2.crypto.cipher;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test ChaCha20-Poly1305 using the worked example from
 * draft-ietf-sshm-chacha20-poly1305-02, Appendix A.
 */
public class ChaCha20Poly1305Test
{
	@Test
	public void testRfcWorkingExample()
	{
		// Complete test from draft-ietf-sshm-chacha20-poly1305-02 Appendix A
		// Key material from RFC Appendix A (Figure 5)
		byte[] keyMaterial = new byte[] {
			(byte) 0x8b, (byte) 0xbf, (byte) 0xf6, (byte) 0x85, (byte) 0x5f, (byte) 0xc1, (byte) 0x02, (byte) 0x33,
			(byte) 0x8c, (byte) 0x37, (byte) 0x3e, (byte) 0x73, (byte) 0xaa, (byte) 0xc0, (byte) 0xc9, (byte) 0x14,
			(byte) 0xf0, (byte) 0x76, (byte) 0xa9, (byte) 0x05, (byte) 0xb2, (byte) 0x44, (byte) 0x4a, (byte) 0x32,
			(byte) 0xee, (byte) 0xca, (byte) 0xff, (byte) 0xea, (byte) 0xe2, (byte) 0x2b, (byte) 0xec, (byte) 0xc5,
			(byte) 0xe9, (byte) 0xb7, (byte) 0xa7, (byte) 0xa5, (byte) 0x82, (byte) 0x5a, (byte) 0x82, (byte) 0x49,
			(byte) 0x34, (byte) 0x6e, (byte) 0xc1, (byte) 0xc2, (byte) 0x83, (byte) 0x01, (byte) 0xcf, (byte) 0x39,
			(byte) 0x45, (byte) 0x43, (byte) 0xfc, (byte) 0x75, (byte) 0x69, (byte) 0x88, (byte) 0x7d, (byte) 0x76,
			(byte) 0xe1, (byte) 0x68, (byte) 0xf3, (byte) 0x75, (byte) 0x62, (byte) 0xac, (byte) 0x07, (byte) 0x40
		};

		// Sequence number 7 (from RFC example)
		int seqNum = 7;

		// Plaintext packet data (Figure 4) - 72 bytes after the 4-byte length field
		byte[] plaintext = new byte[] {
			(byte) 0x06, (byte) 0x5e, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x38, (byte) 0x4c, (byte) 0x6f, (byte) 0x72, (byte) 0x65, (byte) 0x6d, (byte) 0x20,
			(byte) 0x69, (byte) 0x70, (byte) 0x73, (byte) 0x75, (byte) 0x6d, (byte) 0x20, (byte) 0x64, (byte) 0x6f,
			(byte) 0x6c, (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x73, (byte) 0x69, (byte) 0x74, (byte) 0x20,
			(byte) 0x61, (byte) 0x6d, (byte) 0x65, (byte) 0x74, (byte) 0x2c, (byte) 0x20, (byte) 0x63, (byte) 0x6f,
			(byte) 0x6e, (byte) 0x73, (byte) 0x65, (byte) 0x63, (byte) 0x74, (byte) 0x65, (byte) 0x74, (byte) 0x75,
			(byte) 0x72, (byte) 0x20, (byte) 0x61, (byte) 0x64, (byte) 0x69, (byte) 0x70, (byte) 0x69, (byte) 0x73,
			(byte) 0x69, (byte) 0x63, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20, (byte) 0x65, (byte) 0x6c,
			(byte) 0x69, (byte) 0x74, (byte) 0x4e, (byte) 0x43, (byte) 0xe8, (byte) 0x04, (byte) 0xdc, (byte) 0x6c
		};

		// Expected encrypted length (Figure 8)
		byte[] expectedEncryptedLength = new byte[] {
			(byte) 0x2c, (byte) 0x3e, (byte) 0xcc, (byte) 0xe4
		};

		// Expected ciphertext (Figure 11)
		byte[] expectedCiphertext = new byte[] {
			(byte) 0xa5, (byte) 0xbc, (byte) 0x05, (byte) 0x89, (byte) 0x5b, (byte) 0xf0, (byte) 0x7a, (byte) 0x7b,
			(byte) 0xa9, (byte) 0x56, (byte) 0xb6, (byte) 0xc6, (byte) 0x88, (byte) 0x29, (byte) 0xac, (byte) 0x7c,
			(byte) 0x83, (byte) 0xb7, (byte) 0x80, (byte) 0xb7, (byte) 0x00, (byte) 0x0e, (byte) 0xcd, (byte) 0xe7,
			(byte) 0x45, (byte) 0xaf, (byte) 0xc7, (byte) 0x05, (byte) 0xbb, (byte) 0xc3, (byte) 0x78, (byte) 0xce,
			(byte) 0x03, (byte) 0xa2, (byte) 0x80, (byte) 0x23, (byte) 0x6b, (byte) 0x87, (byte) 0xb5, (byte) 0x3b,
			(byte) 0xed, (byte) 0x58, (byte) 0x39, (byte) 0x66, (byte) 0x23, (byte) 0x02, (byte) 0xb1, (byte) 0x64,
			(byte) 0xb6, (byte) 0x28, (byte) 0x6a, (byte) 0x48, (byte) 0xcd, (byte) 0x1e, (byte) 0x09, (byte) 0x71,
			(byte) 0x38, (byte) 0xe3, (byte) 0xcb, (byte) 0x90, (byte) 0x9b, (byte) 0x8b, (byte) 0x2b, (byte) 0x82,
			(byte) 0x9d, (byte) 0xd1, (byte) 0x8d, (byte) 0x2a, (byte) 0x35, (byte) 0xff, (byte) 0x82, (byte) 0xd9
		};

		// Expected Poly1305 tag (Figure 17)
		byte[] expectedTag = new byte[] {
			(byte) 0x95, (byte) 0x34, (byte) 0x9e, (byte) 0x85, (byte) 0x5b, (byte) 0xf0, (byte) 0x2c, (byte) 0x29,
			(byte) 0x8e, (byte) 0xf7, (byte) 0x75, (byte) 0xf2, (byte) 0xd1, (byte) 0xa7, (byte) 0xe8, (byte) 0xb8
		};

		ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
		cipher.init(true, keyMaterial, null);

		// Test 1: Length encryption
		byte[] plainLength = new byte[] { 0x00, 0x00, 0x00, 0x48 };
		byte[] encryptedLength = new byte[4];
		cipher.encryptPacketLength(seqNum, plainLength, encryptedLength, 0);
		assertArrayEquals(expectedEncryptedLength, encryptedLength,
			"Encrypted length should match RFC example (Figure 8)");

		// Test 2: Full packet encryption and MAC
		byte[] ciphertext = new byte[plaintext.length];
		byte[] tag = new byte[16];
		cipher.seal(seqNum, plaintext, ciphertext, tag, encryptedLength);

		assertArrayEquals(expectedCiphertext, ciphertext,
			"Ciphertext should match RFC example (Figure 11)");
		assertArrayEquals(expectedTag, tag,
			"Poly1305 tag should match RFC example (Figure 17)");

		// Test 3: Decryption
		ChaCha20Poly1305 decCipher = new ChaCha20Poly1305();
		decCipher.init(false, keyMaterial, null);

		byte[] decryptedLength = new byte[4];
		decCipher.decryptPacketLength(seqNum, encryptedLength, decryptedLength, 0);
		assertArrayEquals(plainLength, decryptedLength,
			"Decrypted length should match original");

		byte[] decrypted = new byte[plaintext.length];
		boolean valid = decCipher.open(seqNum, ciphertext, tag, decrypted, encryptedLength);
		assertTrue(valid, "Tag verification should succeed");
		assertArrayEquals(plaintext, decrypted,
			"Decrypted plaintext should match original (Figure 4)");
	}

	@Test
	public void testEncryptDecryptRoundTrip()
	{
		byte[] key = new byte[64];
		// Initialize with test key
		for (int i = 0; i < 64; i++)
		{
			key[i] = (byte) i;
		}

		ChaCha20Poly1305 encCipher = new ChaCha20Poly1305();
		encCipher.init(true, key, null);

		ChaCha20Poly1305 decCipher = new ChaCha20Poly1305();
		decCipher.init(false, key, null);

		byte[] plaintext = "Hello, ChaCha20-Poly1305!".getBytes();
		byte[] lengthBytes = new byte[] { 0x00, 0x00, 0x00, 0x19 };

		// Encrypt
		byte[] encLength = new byte[4];
		encCipher.encryptPacketLength(0, lengthBytes, encLength, 0);

		byte[] ciphertext = new byte[plaintext.length];
		byte[] tag = new byte[16];
		encCipher.seal(0, plaintext, ciphertext, tag, encLength);

		// Decrypt
		byte[] decLength = new byte[4];
		decCipher.decryptPacketLength(0, encLength, decLength, 0);

		byte[] decrypted = new byte[plaintext.length];
		boolean valid = decCipher.open(0, ciphertext, tag, decrypted, encLength);

		assertTrue(valid, "Tag verification should succeed");
		assertArrayEquals(lengthBytes, decLength, "Length should decrypt correctly");
		assertArrayEquals(plaintext, decrypted, "Plaintext should decrypt correctly");
	}

	@Test
	public void testTagVerificationFailure()
	{
		byte[] key = new byte[64];
		ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
		cipher.init(false, key, null);

		byte[] ciphertext = new byte[32];
		byte[] badTag = new byte[16]; // All zeros - invalid
		byte[] plaintext = new byte[32];
		byte[] encLength = new byte[4];

		boolean valid = cipher.open(0, ciphertext, badTag, plaintext, encLength);

		assertFalse(valid, "Tag verification should fail with invalid tag");
	}

	@Test
	public void testSequenceNumbers()
	{
		byte[] key = new byte[64];
		for (int i = 0; i < 64; i++)
		{
			key[i] = (byte) (i * 2);
		}

		ChaCha20Poly1305 encCipher = new ChaCha20Poly1305();
		encCipher.init(true, key, null);

		ChaCha20Poly1305 decCipher = new ChaCha20Poly1305();
		decCipher.init(false, key, null);

		byte[] plaintext = "Test message".getBytes();

		// Test different sequence numbers
		for (int seqNum = 0; seqNum < 100; seqNum++)
		{
			byte[] lengthBytes = new byte[] { 0x00, 0x00, 0x00, (byte) plaintext.length };

			byte[] encLength = new byte[4];
			encCipher.encryptPacketLength(seqNum, lengthBytes, encLength, 0);

			byte[] ciphertext = new byte[plaintext.length];
			byte[] tag = new byte[16];
			encCipher.seal(seqNum, plaintext, ciphertext, tag, encLength);

			byte[] decrypted = new byte[plaintext.length];
			boolean valid = decCipher.open(seqNum, ciphertext, tag, decrypted, encLength);

			assertTrue(valid, "Tag verification should succeed for seqNum " + seqNum);
			assertArrayEquals(plaintext, decrypted, "Plaintext should match for seqNum " + seqNum);
		}
	}

	@Test
	public void testWrongSequenceNumberFails()
	{
		byte[] key = new byte[64];
		ChaCha20Poly1305 encCipher = new ChaCha20Poly1305();
		encCipher.init(true, key, null);

		ChaCha20Poly1305 decCipher = new ChaCha20Poly1305();
		decCipher.init(false, key, null);

		byte[] plaintext = "Test".getBytes();
		byte[] lengthBytes = new byte[] { 0x00, 0x00, 0x00, 0x04 };

		// Encrypt with sequence number 10
		byte[] encLength = new byte[4];
		encCipher.encryptPacketLength(10, lengthBytes, encLength, 0);

		byte[] ciphertext = new byte[plaintext.length];
		byte[] tag = new byte[16];
		encCipher.seal(10, plaintext, ciphertext, tag, encLength);

		// Try to decrypt with different sequence number
		byte[] decrypted = new byte[plaintext.length];
		boolean valid = decCipher.open(11, ciphertext, tag, decrypted, encLength);

		assertFalse(valid, "Tag verification should fail with wrong sequence number");
	}
}

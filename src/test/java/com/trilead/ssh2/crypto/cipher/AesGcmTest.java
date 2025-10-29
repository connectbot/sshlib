package com.trilead.ssh2.crypto.cipher;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for AES-GCM AEAD cipher implementation.
 *
 * Tests both AES-128-GCM and AES-256-GCM variants with various test vectors
 * and edge cases.
 */
public class AesGcmTest {
	private static final SecureRandom random = new SecureRandom();

	@Test
	public void testAes128GcmRoundTrip() throws Exception {
		AesGcm cipher = new AesGcm(128);

		// Key material: 16 bytes key + 12 bytes IV = 28 bytes
		byte[] keyMaterial = new byte[28];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		// Prepare test data
		byte[] plainLength = { 0x00, 0x00, 0x00, 0x20 }; // 32 bytes
		byte[] payload = "Test payload for AES-GCM encryption".getBytes();
		byte[] ciphertext = new byte[payload.length];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		// Encrypt
		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Decrypt
		AesGcm decipher = new AesGcm(128);
		decipher.init(false, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		byte[] decryptedLength = new byte[4];
		byte[] plaintext = new byte[payload.length];

		decipher.decryptPacketLength(1, encryptedLength, decryptedLength, 0);
		boolean valid = decipher.open(1, ciphertext, tag, plaintext, encryptedLength);

		assertTrue(valid, "Tag verification should succeed");
		assertArrayEquals(payload, plaintext, "Plaintext should match");
		assertArrayEquals(plainLength, decryptedLength, "Length should match (not encrypted for AES-GCM)");
	}

	@Test
	public void testAes256GcmRoundTrip() throws Exception {
		AesGcm cipher = new AesGcm(256);

		// Key material: 32 bytes key + 12 bytes IV = 44 bytes
		byte[] keyMaterial = new byte[44];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		// Prepare test data
		byte[] plainLength = { 0x00, 0x00, 0x00, 0x10 }; // 16 bytes
		byte[] payload = "Test payload 256".getBytes();
		byte[] ciphertext = new byte[payload.length];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		// Encrypt
		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Decrypt
		AesGcm decipher = new AesGcm(256);
		decipher.init(false, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		byte[] decryptedLength = new byte[4];
		byte[] plaintext = new byte[payload.length];

		decipher.decryptPacketLength(1, encryptedLength, decryptedLength, 0);
		boolean valid = decipher.open(1, ciphertext, tag, plaintext, encryptedLength);

		assertTrue(valid, "Tag verification should succeed");
		assertArrayEquals(payload, plaintext, "Plaintext should match");
	}

	@Test
	public void testAes128GcmInvalidTag() throws Exception {
		AesGcm cipher = new AesGcm(128);
		byte[] keyMaterial = new byte[28];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		byte[] plainLength = { 0x00, 0x00, 0x00, 0x10 };
		byte[] payload = "Test payload".getBytes();
		byte[] ciphertext = new byte[payload.length];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Corrupt tag
		tag[tag.length - 1] ^= 0xFF;

		// Decrypt should fail
		AesGcm decipher = new AesGcm(128);
		decipher.init(false, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		byte[] plaintext = new byte[payload.length];

		boolean valid = decipher.open(1, ciphertext, tag, plaintext, encryptedLength);

		assertFalse(valid, "Tag verification should fail");
	}

	@Test
	public void testAes256GcmInvalidTag() throws Exception {
		AesGcm cipher = new AesGcm(256);
		byte[] keyMaterial = new byte[44];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		byte[] plainLength = { 0x00, 0x00, 0x00, 0x10 };
		byte[] payload = "Test payload".getBytes();
		byte[] ciphertext = new byte[payload.length];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Corrupt tag (first byte)
		tag[0] ^= 0xFF;

		// Decrypt should fail
		AesGcm decipher = new AesGcm(256);
		decipher.init(false, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		byte[] plaintext = new byte[payload.length];

		boolean valid = decipher.open(1, ciphertext, tag, plaintext, encryptedLength);

		assertFalse(valid, "Tag verification should fail");
	}

	@Test
	public void testNonceUniqueness() throws Exception {
		AesGcm cipher = new AesGcm(128);
		byte[] keyMaterial = new byte[28];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		byte[] plainLength = { 0x00, 0x00, 0x00, 0x10 };
		byte[] payload = "Test payload".getBytes();
		byte[] encryptedLength = new byte[4];

		// Encrypt same plaintext with different sequence numbers
		byte[] ciphertext1 = new byte[payload.length];
		byte[] tag1 = new byte[16];
		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext1, tag1, encryptedLength);

		byte[] ciphertext2 = new byte[payload.length];
		byte[] tag2 = new byte[16];
		cipher.encryptPacketLength(2, plainLength, encryptedLength, 0);
		cipher.seal(2, payload, ciphertext2, tag2, encryptedLength);

		// Ciphertexts should be different due to different nonces
		assertFalse(Arrays.equals(ciphertext1, ciphertext2),
				"Ciphertexts should differ with different sequence numbers");
		assertFalse(Arrays.equals(tag1, tag2),
				"Tags should differ with different sequence numbers");
	}

	@Test
	public void testAADModification() throws Exception {
		AesGcm cipher = new AesGcm(128);
		byte[] keyMaterial = new byte[28];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		byte[] plainLength = { 0x00, 0x00, 0x00, 0x10 };
		byte[] payload = "Test payload".getBytes();
		byte[] ciphertext = new byte[payload.length];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Modify AAD (the length field)
		byte[] modifiedLength = encryptedLength.clone();
		modifiedLength[3] ^= 0x01;

		// Decrypt with modified AAD should fail
		AesGcm decipher = new AesGcm(128);
		decipher.init(false, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		byte[] plaintext = new byte[payload.length];

		boolean valid = decipher.open(1, ciphertext, tag, plaintext, modifiedLength);

		assertFalse(valid, "Tag verification should fail when AAD is modified");
	}

	@Test
	public void testCiphertextModification() throws Exception {
		AesGcm cipher = new AesGcm(128);
		byte[] keyMaterial = new byte[28];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		byte[] plainLength = { 0x00, 0x00, 0x00, 0x10 };
		byte[] payload = "Test payload".getBytes();
		byte[] ciphertext = new byte[payload.length];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Modify ciphertext
		ciphertext[0] ^= 0xFF;

		// Decrypt should fail
		AesGcm decipher = new AesGcm(128);
		decipher.init(false, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		byte[] plaintext = new byte[payload.length];

		boolean valid = decipher.open(1, ciphertext, tag, plaintext, encryptedLength);

		assertFalse(valid, "Tag verification should fail when ciphertext is modified");
	}

	@Test
	public void testMultiplePackets() throws Exception {
		AesGcm cipher = new AesGcm(128);
		byte[] keyMaterial = new byte[28];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		AesGcm decipher = new AesGcm(128);
		decipher.init(false, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		// Send multiple packets
		for (int i = 0; i < 100; i++) {
			byte[] plainLength = { 0x00, 0x00, 0x00, 0x10 };
			byte[] payload = ("Packet " + i).getBytes();
			byte[] ciphertext = new byte[payload.length];
			byte[] tag = new byte[16];
			byte[] encryptedLength = new byte[4];

			cipher.encryptPacketLength(i, plainLength, encryptedLength, 0);
			cipher.seal(i, payload, ciphertext, tag, encryptedLength);

			byte[] plaintext = new byte[payload.length];
			boolean valid = decipher.open(i, ciphertext, tag, plaintext, encryptedLength);

			assertTrue(valid, "Packet " + i + " should verify successfully");
			assertArrayEquals(payload, plaintext, "Packet " + i + " plaintext should match");
		}
	}

	@Test
	public void testEmptyPayload() throws Exception {
		AesGcm cipher = new AesGcm(128);
		byte[] keyMaterial = new byte[28];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		byte[] plainLength = { 0x00, 0x00, 0x00, 0x00 };
		byte[] payload = new byte[0];
		byte[] ciphertext = new byte[0];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Decrypt
		AesGcm decipher = new AesGcm(128);
		decipher.init(false, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		byte[] plaintext = new byte[0];

		boolean valid = decipher.open(1, ciphertext, tag, plaintext, encryptedLength);

		assertTrue(valid, "Tag verification should succeed for empty payload");
	}

	@Test
	public void testLargePayload() throws Exception {
		AesGcm cipher = new AesGcm(256);
		byte[] keyMaterial = new byte[44];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		// Test with 32KB payload
		byte[] payload = new byte[32768];
		random.nextBytes(payload);

		byte[] plainLength = { 0x00, 0x00, (byte) 0x80, 0x00 };
		byte[] ciphertext = new byte[payload.length];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Decrypt
		AesGcm decipher = new AesGcm(256);
		decipher.init(false, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		byte[] plaintext = new byte[payload.length];

		boolean valid = decipher.open(1, ciphertext, tag, plaintext, encryptedLength);

		assertTrue(valid, "Tag verification should succeed for large payload");
		assertArrayEquals(payload, plaintext, "Large payload should match");
	}

	@Test
	public void testInvalidKeySize() {
		assertThrows(IllegalArgumentException.class, () -> {
			new AesGcm(192); // Only 128 and 256 are supported
		});
	}

	@Test
	public void testInvalidKeyMaterialLength128() {
		assertThrows(IllegalArgumentException.class, () -> {
			AesGcm cipher = new AesGcm(128);
			byte[] keyMaterial = new byte[27]; // Should be 28
			cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
					Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		});
	}

	@Test
	public void testInvalidKeyMaterialLength256() {
		assertThrows(IllegalArgumentException.class, () -> {
			AesGcm cipher = new AesGcm(256);
			byte[] keyMaterial = new byte[43]; // Should be 44
			cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
					Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));
		});
	}

	@Test
	public void testGetKeySize() {
		AesGcm cipher128 = new AesGcm(128);
		assertEquals(16, cipher128.getKeySize());

		AesGcm cipher256 = new AesGcm(256);
		assertEquals(32, cipher256.getKeySize());
	}

	@Test
	public void testGetTagSize() {
		AesGcm cipher = new AesGcm(128);
		assertEquals(16, cipher.getTagSize());
	}

	@Test
	public void testLengthNotEncrypted() throws Exception {
		// Verify that AES-GCM does NOT encrypt the length field
		AesGcm cipher = new AesGcm(128);
		byte[] keyMaterial = new byte[28];
		random.nextBytes(keyMaterial);

		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		byte[] plainLength = { 0x01, 0x02, 0x03, 0x04 };
		byte[] encryptedLength = new byte[4];

		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);

		// For AES-GCM, length should be copied as-is (not encrypted)
		assertArrayEquals(plainLength, encryptedLength, "Length should not be encrypted for AES-GCM");
	}

	@Test
	public void testInnerClassAES128() throws Exception {
		AesGcm.AES128 cipher = new AesGcm.AES128();
		assertEquals(16, cipher.getKeySize());

		byte[] keyMaterial = new byte[28];
		random.nextBytes(keyMaterial);
		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		byte[] plainLength = { 0x00, 0x00, 0x00, 0x10 };
		byte[] payload = "Test".getBytes();
		byte[] ciphertext = new byte[payload.length];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Verify tag is generated
		boolean allZeros = true;
		for (byte b : tag) {
			if (b != 0) {
				allZeros = false;
				break;
			}
		}
		assertFalse(allZeros, "Tag should not be all zeros");
	}

	@Test
	public void testInnerClassAES256() throws Exception {
		AesGcm.AES256 cipher = new AesGcm.AES256();
		assertEquals(32, cipher.getKeySize());

		byte[] keyMaterial = new byte[44];
		random.nextBytes(keyMaterial);
		cipher.init(true, Arrays.copyOfRange(keyMaterial, 0, keyMaterial.length - 12),
				Arrays.copyOfRange(keyMaterial, keyMaterial.length - 12, keyMaterial.length));

		byte[] plainLength = { 0x00, 0x00, 0x00, 0x10 };
		byte[] payload = "Test".getBytes();
		byte[] ciphertext = new byte[payload.length];
		byte[] tag = new byte[16];
		byte[] encryptedLength = new byte[4];

		cipher.encryptPacketLength(1, plainLength, encryptedLength, 0);
		cipher.seal(1, payload, ciphertext, tag, encryptedLength);

		// Verify tag is generated
		boolean allZeros = true;
		for (byte b : tag) {
			if (b != 0) {
				allZeros = false;
				break;
			}
		}
		assertFalse(allZeros, "Tag should not be all zeros");
	}
}

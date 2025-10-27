package com.trilead.ssh2.crypto.cipher;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Test coverage for Blowfish cipher implementation.
 * Test vectors from Bruce Schneier's original Blowfish specification and other sources.
 */
public class BlowfishTest {

	private static byte[] toBytes(String hexString) {
		try {
			return Hex.decodeHex(hexString);
		} catch (DecoderException e) {
			throw new AssertionError("Cannot decode test vector: " + hexString);
		}
	}

	@Test
	public void testGetBlockSize() {
		BlowFish cipher = new BlowFish();
		assertEquals(8, cipher.getBlockSize());
	}

	@Test
	public void testGetAlgorithmName() {
		BlowFish cipher = new BlowFish();
		assertEquals("Blowfish", cipher.getAlgorithmName());
	}

	@Test(expected = IllegalStateException.class)
	public void testTransformBlockWithoutInit() {
		BlowFish cipher = new BlowFish();
		byte[] input = new byte[8];
		byte[] output = new byte[8];
		cipher.transformBlock(input, 0, output, 0);
	}

	@Test
	public void testEncryptDecryptBasic() {
		BlowFish cipher = new BlowFish();
		byte[] key = "testkey1".getBytes();
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("0000000000000000");
		byte[] ciphertext = new byte[8];
		cipher.transformBlock(plaintext, 0, ciphertext, 0);

		// Now decrypt
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(ciphertext, 0, decrypted, 0);

		assertArrayEquals(plaintext, decrypted);
	}

	@Test
	public void testEncryptDecryptWithOffset() {
		BlowFish cipher = new BlowFish();
		byte[] key = "mykey123".getBytes();
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = new byte[16];
		for (int i = 0; i < 16; i++) {
			plaintext[i] = (byte) i;
		}

		byte[] ciphertext = new byte[16];
		cipher.transformBlock(plaintext, 8, ciphertext, 8);

		// Decrypt
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[16];
		cipher.transformBlock(ciphertext, 8, decrypted, 8);

		// Check only the transformed block
		for (int i = 8; i < 16; i++) {
			assertEquals(plaintext[i], decrypted[i]);
		}
	}

	/**
	 * Test vector from Bruce Schneier's original Blowfish test vectors
	 */
	@Test
	public void testBlowfishTestVector1() {
		BlowFish cipher = new BlowFish();
		byte[] key = toBytes("0000000000000000");
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("0000000000000000");
		byte[] expected = toBytes("4EF997456198DD78");
		byte[] actual = new byte[8];

		cipher.transformBlock(plaintext, 0, actual, 0);
		assertArrayEquals(expected, actual);

		// Test decryption
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(actual, 0, decrypted, 0);
		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test vector from Bruce Schneier's original Blowfish test vectors
	 */
	@Test
	public void testBlowfishTestVector2() {
		BlowFish cipher = new BlowFish();
		byte[] key = toBytes("FFFFFFFFFFFFFFFF");
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("FFFFFFFFFFFFFFFF");
		byte[] expected = toBytes("51866FD5B85ECB8A");
		byte[] actual = new byte[8];

		cipher.transformBlock(plaintext, 0, actual, 0);
		assertArrayEquals(expected, actual);

		// Test decryption
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(actual, 0, decrypted, 0);
		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test vector from Bruce Schneier's original Blowfish test vectors
	 */
	@Test
	public void testBlowfishTestVector3() {
		BlowFish cipher = new BlowFish();
		byte[] key = toBytes("3000000000000000");
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("1000000000000001");
		byte[] expected = toBytes("7D856F9A613063F2");
		byte[] actual = new byte[8];

		cipher.transformBlock(plaintext, 0, actual, 0);
		assertArrayEquals(expected, actual);
	}

	/**
	 * Test vector with variable-length key (56 bits)
	 */
	@Test
	public void testBlowfishVariableKeyLength7Bytes() {
		BlowFish cipher = new BlowFish();
		byte[] key = toBytes("0123456789ABCD");
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("0000000000000000");
		byte[] actual = new byte[8];
		cipher.transformBlock(plaintext, 0, actual, 0);

		// Decrypt to verify
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(actual, 0, decrypted, 0);
		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test vector with maximum key length (56 bytes / 448 bits)
	 */
	@Test
	public void testBlowfishMaxKeyLength() {
		BlowFish cipher = new BlowFish();
		byte[] key = new byte[56]; // Maximum Blowfish key length
		for (int i = 0; i < key.length; i++) {
			key[i] = (byte) i;
		}
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("0123456789ABCDEF");
		byte[] actual = new byte[8];
		cipher.transformBlock(plaintext, 0, actual, 0);

		// Decrypt to verify
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(actual, 0, decrypted, 0);
		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test multiple blocks encryption/decryption
	 */
	@Test
	public void testMultipleBlocks() {
		BlowFish cipher = new BlowFish();
		byte[] key = "secret".getBytes();
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = new byte[32]; // 4 blocks
		for (int i = 0; i < plaintext.length; i++) {
			plaintext[i] = (byte) (i % 256);
		}

		byte[] ciphertext = new byte[32];
		for (int i = 0; i < 4; i++) {
			cipher.transformBlock(plaintext, i * 8, ciphertext, i * 8);
		}

		// Decrypt
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[32];
		for (int i = 0; i < 4; i++) {
			cipher.transformBlock(ciphertext, i * 8, decrypted, i * 8);
		}

		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test that re-initialization works correctly
	 */
	@Test
	public void testReinitialization() {
		BlowFish cipher = new BlowFish();
		byte[] key1 = "key1".getBytes();
		byte[] key2 = "key2".getBytes();
		byte[] iv = new byte[8];
		byte[] plaintext = toBytes("0123456789ABCDEF");

		// First encryption with key1
		cipher.init(true, key1, iv);
		byte[] cipher1 = new byte[8];
		cipher.transformBlock(plaintext, 0, cipher1, 0);

		// Second encryption with key2
		cipher.init(true, key2, iv);
		byte[] cipher2 = new byte[8];
		cipher.transformBlock(plaintext, 0, cipher2, 0);

		// The ciphertexts should be different
		boolean different = false;
		for (int i = 0; i < 8; i++) {
			if (cipher1[i] != cipher2[i]) {
				different = true;
				break;
			}
		}
		if (!different) {
			fail("Ciphertexts with different keys should be different");
		}

		// Verify decryption with key1
		cipher.init(false, key1, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(cipher1, 0, decrypted, 0);
		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test CBC mode wrapper
	 */
	@Test
	public void testCBCMode() {
		BlowFish.CBC cipher = new BlowFish.CBC();
		byte[] key = toBytes("0123456789ABCDEF");
		byte[] iv = toBytes("FEDCBA9876543210");

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("0123456789ABCDEF");
		byte[] ciphertext = new byte[8];
		cipher.transformBlock(plaintext, 0, ciphertext, 0);

		// Decrypt
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(ciphertext, 0, decrypted, 0);

		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test CTR mode wrapper
	 */
	@Test
	public void testCTRMode() {
		BlowFish.CTR cipher = new BlowFish.CTR();
		byte[] key = toBytes("0123456789ABCDEF");
		byte[] iv = toBytes("FEDCBA9876543210");

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("0123456789ABCDEF");
		byte[] ciphertext = new byte[8];
		cipher.transformBlock(plaintext, 0, ciphertext, 0);

		// Decrypt (CTR mode uses same operation for encrypt/decrypt)
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(ciphertext, 0, decrypted, 0);

		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test CBC mode with BlockCipherFactory
	 */
	@Test
	public void testBlowfishCBCViaFactory() {
		byte[] key = toBytes("0123456789ABCDEF");
		byte[] iv = toBytes("FEDCBA9876543210");

		BlockCipher encryptCipher = BlockCipherFactory.createCipher("blowfish-cbc", true, key, iv);
		byte[] plaintext = toBytes("0123456789ABCDEF");
		byte[] ciphertext = new byte[8];
		encryptCipher.transformBlock(plaintext, 0, ciphertext, 0);

		BlockCipher decryptCipher = BlockCipherFactory.createCipher("blowfish-cbc", false, key, iv);
		byte[] decrypted = new byte[8];
		decryptCipher.transformBlock(ciphertext, 0, decrypted, 0);

		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test CTR mode with BlockCipherFactory
	 */
	@Test
	public void testBlowfishCTRViaFactory() {
		byte[] key = toBytes("0123456789ABCDEF");
		byte[] iv = toBytes("FEDCBA9876543210");

		BlockCipher encryptCipher = BlockCipherFactory.createCipher("blowfish-ctr", true, key, iv);
		byte[] plaintext = toBytes("0123456789ABCDEF");
		byte[] ciphertext = new byte[8];
		encryptCipher.transformBlock(plaintext, 0, ciphertext, 0);

		BlockCipher decryptCipher = BlockCipherFactory.createCipher("blowfish-ctr", false, key, iv);
		byte[] decrypted = new byte[8];
		decryptCipher.transformBlock(ciphertext, 0, decrypted, 0);

		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test that block size is consistent across modes
	 */
	@Test
	public void testBlockSizeConsistency() {
		BlowFish rawCipher = new BlowFish();
		BlowFish.CBC cbcCipher = new BlowFish.CBC();
		BlowFish.CTR ctrCipher = new BlowFish.CTR();

		assertEquals(8, rawCipher.getBlockSize());

		byte[] key = new byte[16];
		byte[] iv = new byte[8];

		cbcCipher.init(true, key, iv);
		assertEquals(8, cbcCipher.getBlockSize());

		ctrCipher.init(true, key, iv);
		assertEquals(8, ctrCipher.getBlockSize());
	}

	/**
	 * Test encryption and decryption mode flag
	 */
	@Test
	public void testEncryptDecryptModeFlag() {
		BlowFish cipher = new BlowFish();
		byte[] key = toBytes("0123456789ABCDEF");
		byte[] iv = new byte[8];
		byte[] plaintext = toBytes("FEDCBA9876543210");

		// Encrypt
		cipher.init(true, key, iv);
		byte[] encrypted = new byte[8];
		cipher.transformBlock(plaintext, 0, encrypted, 0);

		// Try to decrypt with same cipher instance (should work after re-init)
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(encrypted, 0, decrypted, 0);

		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test with minimum key size (1 byte)
	 */
	@Test
	public void testMinimumKeySize() {
		BlowFish cipher = new BlowFish();
		byte[] key = new byte[]{0x42};
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("0000000000000000");
		byte[] ciphertext = new byte[8];
		cipher.transformBlock(plaintext, 0, ciphertext, 0);

		// Decrypt to verify
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(ciphertext, 0, decrypted, 0);
		assertArrayEquals(plaintext, decrypted);
	}

	/**
	 * Test with SSH standard key size (16 bytes / 128 bits)
	 */
	@Test
	public void testSSHStandardKeySize() {
		BlowFish cipher = new BlowFish();
		byte[] key = new byte[16]; // SSH standard for Blowfish
		for (int i = 0; i < key.length; i++) {
			key[i] = (byte) (i * 17); // Generate some pattern
		}
		byte[] iv = new byte[8];

		cipher.init(true, key, iv);

		byte[] plaintext = toBytes("DEADBEEFCAFEBABE");
		byte[] ciphertext = new byte[8];
		cipher.transformBlock(plaintext, 0, ciphertext, 0);

		// Decrypt to verify
		cipher.init(false, key, iv);
		byte[] decrypted = new byte[8];
		cipher.transformBlock(ciphertext, 0, decrypted, 0);
		assertArrayEquals(plaintext, decrypted);
	}
}

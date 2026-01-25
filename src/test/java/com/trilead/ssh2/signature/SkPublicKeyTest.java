package com.trilead.ssh2.signature;

import com.trilead.ssh2.packets.TypesWriter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for the SkPublicKey interface.
 */
public class SkPublicKeyTest {

	private static final String SK_ED25519_KEY_TYPE = "sk-ssh-ed25519@openssh.com";
	private static final String SK_ECDSA_KEY_TYPE = "sk-ecdsa-sha2-nistp256@openssh.com";
	private static final String DEFAULT_APPLICATION = "ssh:";
	private static final byte[] TEST_KEY_DATA = new byte[] {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
	};

	/**
	 * Test implementation of SkPublicKey for unit testing.
	 */
	static class TestSkPublicKey implements SkPublicKey {
		private final String keyType;
		private final String application;
		private final byte[] keyData;

		TestSkPublicKey(String keyType, String application, byte[] keyData) {
			this.keyType = keyType;
			this.application = application;
			this.keyData = keyData.clone();
		}

		@Override
		public String getSshKeyType() {
			return keyType;
		}

		@Override
		public String getApplication() {
			return application;
		}

		@Override
		public byte[] getKeyData() {
			return keyData.clone();
		}

		@Override
		public String getAlgorithm() {
			return keyType;
		}

		@Override
		public String getFormat() {
			return "SSH";
		}

		@Override
		public byte[] getEncoded() {
			TypesWriter tw = new TypesWriter();
			tw.writeString(keyType);
			tw.writeString(keyData, 0, keyData.length);
			tw.writeString(application);
			return tw.getBytes();
		}
	}

	@Test
	public void testSkEd25519KeyType() {
		SkPublicKey key = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);
		assertEquals(SK_ED25519_KEY_TYPE, key.getSshKeyType());
	}

	@Test
	public void testSkEcdsaKeyType() {
		SkPublicKey key = new TestSkPublicKey(SK_ECDSA_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);
		assertEquals(SK_ECDSA_KEY_TYPE, key.getSshKeyType());
	}

	@Test
	public void testApplicationId() {
		SkPublicKey key = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);
		assertEquals(DEFAULT_APPLICATION, key.getApplication());
	}

	@Test
	public void testCustomApplicationId() {
		String customApp = "custom:app";
		SkPublicKey key = new TestSkPublicKey(SK_ED25519_KEY_TYPE, customApp, TEST_KEY_DATA);
		assertEquals(customApp, key.getApplication());
	}

	@Test
	public void testKeyData() {
		SkPublicKey key = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);
		assertArrayEquals(TEST_KEY_DATA, key.getKeyData());
	}

	@Test
	public void testEncodedFormat() {
		SkPublicKey key = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);

		byte[] encoded = key.getEncoded();

		// Verify the encoded format contains key type, key data, and application
		// The encoding should be: key_type_string + key_data_string + application_string
		TypesWriter expected = new TypesWriter();
		expected.writeString(SK_ED25519_KEY_TYPE);
		expected.writeString(TEST_KEY_DATA, 0, TEST_KEY_DATA.length);
		expected.writeString(DEFAULT_APPLICATION);

		assertArrayEquals(expected.getBytes(), encoded);
	}

	@Test
	public void testAlgorithmReturnsKeyType() {
		SkPublicKey key = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);
		assertEquals(SK_ED25519_KEY_TYPE, key.getAlgorithm());
	}

	@Test
	public void testKeyDataIsolation() {
		byte[] originalData = TEST_KEY_DATA.clone();
		TestSkPublicKey key = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, originalData);

		// Modify the original data
		originalData[0] = (byte) 0xFF;

		// The key's data should not be affected
		assertArrayEquals(TEST_KEY_DATA, key.getKeyData());
	}
}

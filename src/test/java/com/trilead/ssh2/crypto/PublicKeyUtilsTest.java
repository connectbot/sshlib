package com.trilead.ssh2.crypto;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicKeyUtilsTest {

	private static final String TEST_RESOURCES = "src/test/resources/key-encoder-decoder-tests/";

	@Test
	void testToAuthorizedKeysFormatRSA() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_rsa_2048";
		String pubPath = TEST_RESOURCES + "openssh_rsa_2048.pub";

		KeyPair keyPair = loadKeyPair(keyPath);
		String expected = loadPublicKeyString(pubPath);

		String result = PublicKeyUtils.toAuthorizedKeysFormat(keyPair.getPublic(), "test-rsa-2048");

		assertEquals(expected.trim(), result.trim());
	}

	@Test
	void testToAuthorizedKeysFormatEd25519() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_ed25519";
		String pubPath = TEST_RESOURCES + "openssh_ed25519.pub";

		KeyPair keyPair = loadKeyPair(keyPath);
		String expected = loadPublicKeyString(pubPath);

		String result = PublicKeyUtils.toAuthorizedKeysFormat(keyPair.getPublic(), "test-ed25519");

		assertEquals(expected.trim(), result.trim());
	}

	@Test
	void testToAuthorizedKeysFormatECDSA256() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_ecdsa_256";
		String pubPath = TEST_RESOURCES + "openssh_ecdsa_256.pub";

		KeyPair keyPair = loadKeyPair(keyPath);
		String expected = loadPublicKeyString(pubPath);

		String result = PublicKeyUtils.toAuthorizedKeysFormat(keyPair.getPublic(), "test-ecdsa-256");

		assertEquals(expected.trim(), result.trim());
	}

	@Test
	void testToAuthorizedKeysFormatECDSA384() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_ecdsa_384";
		String pubPath = TEST_RESOURCES + "openssh_ecdsa_384.pub";

		KeyPair keyPair = loadKeyPair(keyPath);
		String expected = loadPublicKeyString(pubPath);

		String result = PublicKeyUtils.toAuthorizedKeysFormat(keyPair.getPublic(), "test-ecdsa-384");

		assertEquals(expected.trim(), result.trim());
	}

	@Test
	void testToAuthorizedKeysFormatECDSA521() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_ecdsa_521";
		String pubPath = TEST_RESOURCES + "openssh_ecdsa_521.pub";

		KeyPair keyPair = loadKeyPair(keyPath);
		String expected = loadPublicKeyString(pubPath);

		String result = PublicKeyUtils.toAuthorizedKeysFormat(keyPair.getPublic(), "test-ecdsa-521");

		assertEquals(expected.trim(), result.trim());
	}

	@Test
	void testExtractPublicKeyBlobRSA() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_rsa_2048";
		KeyPair keyPair = loadKeyPair(keyPath);

		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());

		assertNotNull(blob);
		assertTrue(blob.length > 0);

		String blobStr = new String(blob, 0, Math.min(7, blob.length));
		assertTrue(blobStr.contains("ssh-rsa") || blob[0] == 0x00);
	}

	@Test
	void testExtractPublicKeyBlobEd25519() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_ed25519";
		KeyPair keyPair = loadKeyPair(keyPath);

		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());

		assertNotNull(blob);
		assertTrue(blob.length > 0);
	}

	@Test
	void testExtractPublicKeyBlobECDSA() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_ecdsa_256";
		KeyPair keyPair = loadKeyPair(keyPath);

		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());

		assertNotNull(blob);
		assertTrue(blob.length > 0);
	}

	@Test
	void testDetectKeyTypeRSA() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_rsa_2048";
		byte[] keyData = Files.readAllBytes(Paths.get(keyPath));

		String keyType = PublicKeyUtils.detectKeyType(keyData);

		assertEquals("RSA", keyType);
	}

	@Test
	void testDetectKeyTypeEd25519() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_ed25519";
		byte[] keyData = Files.readAllBytes(Paths.get(keyPath));

		String keyType = PublicKeyUtils.detectKeyType(keyData);

		assertEquals("Ed25519", keyType);
	}

	@Test
	void testDetectKeyTypeECDSA() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_ecdsa_256";
		byte[] keyData = Files.readAllBytes(Paths.get(keyPath));

		String keyType = PublicKeyUtils.detectKeyType(keyData);

		assertEquals("EC", keyType);
	}

	@Test
	void testDetectKeyTypeEncryptedRSA() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_rsa_2048_encrypted";
		byte[] keyData = Files.readAllBytes(Paths.get(keyPath));

		String keyType = PublicKeyUtils.detectKeyType(keyData);

		assertEquals("RSA", keyType);
	}

	@Test
	void testDetectKeyTypeStringFormat() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_ed25519";
		String keyString = new String(Files.readAllBytes(Paths.get(keyPath)));

		String keyType = PublicKeyUtils.detectKeyType(keyString);

		assertEquals("Ed25519", keyType);
	}

	@Test
	void testDetectKeyTypeInvalidData() throws Exception {
		byte[] invalidData = "not a valid key".getBytes();

		String keyType = PublicKeyUtils.detectKeyType(invalidData);

		assertNull(keyType);
	}

	@Test
	void testDetectKeyTypePEMFormat() throws Exception {
		String keyPath = TEST_RESOURCES + "pem_rsa_2048";
		byte[] keyData = Files.readAllBytes(Paths.get(keyPath));

		String keyType = PublicKeyUtils.detectKeyType(keyData);

		assertNull(keyType);
	}

	@Test
	void testRoundTripExtractAndFormat() throws Exception {
		String keyPath = TEST_RESOURCES + "openssh_rsa_2048";
		KeyPair keyPair = loadKeyPair(keyPath);

		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());
		String formatted = PublicKeyUtils.toAuthorizedKeysFormat(keyPair.getPublic(), "test");

		assertNotNull(blob);
		assertNotNull(formatted);
		assertTrue(formatted.startsWith("ssh-rsa "));
		assertTrue(formatted.endsWith(" test"));
	}

	private KeyPair loadKeyPair(String path) throws Exception {
		byte[] keyData = Files.readAllBytes(Paths.get(path));
		String keyString = new String(keyData, "UTF-8");
		return PEMDecoder.decode(keyString.toCharArray(), null);
	}

	private String loadPublicKeyString(String path) throws IOException {
		return new String(Files.readAllBytes(Paths.get(path)));
	}
}

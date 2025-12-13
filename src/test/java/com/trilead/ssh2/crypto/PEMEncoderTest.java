package com.trilead.ssh2.crypto;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PEMEncoderTest {

	private static final String TEST_RESOURCES = "src/test/resources/key-encoder-decoder-tests/";
	private static final String TEST_PASSWORD = "test123";

	@Test
	void testEncodeRSAUnencrypted() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_rsa_2048", null);

		String encoded = PEMEncoder.encodeRSAPrivateKey((RSAPrivateCrtKey) keyPair.getPrivate(), null);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN RSA PRIVATE KEY-----"));
		assertTrue(encoded.contains("-----END RSA PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), null);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testEncodeRSAWithAES256() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_rsa_2048", null);

		String encoded = PEMEncoder.encodeRSAPrivateKey(
				(RSAPrivateCrtKey) keyPair.getPrivate(),
				TEST_PASSWORD,
				PEMEncoder.AES_256_CBC);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN RSA PRIVATE KEY-----"));
		assertTrue(encoded.contains("Proc-Type: 4,ENCRYPTED"));
		assertTrue(encoded.contains("DEK-Info: AES-256-CBC"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), TEST_PASSWORD);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testEncodeRSAWithDES3() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_rsa_2048", null);

		String encoded = PEMEncoder.encodeRSAPrivateKey(
				(RSAPrivateCrtKey) keyPair.getPrivate(),
				TEST_PASSWORD,
				PEMEncoder.DES_EDE3_CBC);

		assertNotNull(encoded);
		assertTrue(encoded.contains("DEK-Info: DES-EDE3-CBC"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), TEST_PASSWORD);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testEncodeDSAUnencrypted() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_dsa_aes256", "testpassword");

		String encoded = PEMEncoder.encodeDSAPrivateKey((DSAPrivateKey) keyPair.getPrivate(), null);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN DSA PRIVATE KEY-----"));
		assertTrue(encoded.contains("-----END DSA PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), null);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testEncodeDSAWithAES256() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_dsa_aes256", "testpassword");

		String encoded = PEMEncoder.encodeDSAPrivateKey(
				(DSAPrivateKey) keyPair.getPrivate(),
				TEST_PASSWORD,
				PEMEncoder.AES_256_CBC);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN DSA PRIVATE KEY-----"));
		assertTrue(encoded.contains("Proc-Type: 4,ENCRYPTED"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), TEST_PASSWORD);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testEncodeECUnencrypted() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_ec_256", null);

		String encoded = PEMEncoder.encodeECPrivateKey((ECPrivateKey) keyPair.getPrivate(), null);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN EC PRIVATE KEY-----"));
		assertTrue(encoded.contains("-----END EC PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), null);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testEncodeECWithAES256() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_ec_256", null);

		String encoded = PEMEncoder.encodeECPrivateKey(
				(ECPrivateKey) keyPair.getPrivate(),
				TEST_PASSWORD,
				PEMEncoder.AES_256_CBC);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN EC PRIVATE KEY-----"));
		assertTrue(encoded.contains("Proc-Type: 4,ENCRYPTED"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), TEST_PASSWORD);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testEncodePrivateKeyAutoDetectRSA() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_rsa_2048", null);

		String encoded = PEMEncoder.encodePrivateKey(keyPair.getPrivate(), null);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN RSA PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), null);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testEncodePrivateKeyAutoDetectDSA() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_dsa_aes256", "testpassword");

		String encoded = PEMEncoder.encodePrivateKey(keyPair.getPrivate(), null);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN DSA PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), null);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testEncodePrivateKeyAutoDetectEC() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_ec_256", null);

		String encoded = PEMEncoder.encodePrivateKey(keyPair.getPrivate(), null);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN EC PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), null);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testDefaultEncryptionAlgorithm() throws Exception {
		KeyPair keyPair = loadKeyPair("pem_rsa_2048", null);

		String encoded = PEMEncoder.encodeRSAPrivateKey(
				(RSAPrivateCrtKey) keyPair.getPrivate(),
				TEST_PASSWORD);

		assertTrue(encoded.contains("DEK-Info: AES-256-CBC"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), TEST_PASSWORD);
		assertKeysEqual(keyPair, decoded);
	}

	@Test
	void testRoundTripRSA2048() throws Exception {
		KeyPair original = loadKeyPair("pem_rsa_2048", null);

		String encoded = PEMEncoder.encodePrivateKey(original.getPrivate(), TEST_PASSWORD);
		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), TEST_PASSWORD);

		assertKeysEqual(original, decoded);
	}

	@Test
	void testRoundTripEC384() throws Exception {
		KeyPair original = loadKeyPair("pem_ec_384", null);

		String encoded = PEMEncoder.encodePrivateKey(original.getPrivate(), TEST_PASSWORD);
		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), TEST_PASSWORD);

		assertKeysEqual(original, decoded);
	}

	private KeyPair loadKeyPair(String name, String password) throws Exception {
		String path = TEST_RESOURCES + name;
		byte[] keyData = Files.readAllBytes(Paths.get(path));
		String keyString = new String(keyData, "UTF-8");
		return PEMDecoder.decode(keyString.toCharArray(), password);
	}

	private void assertKeysEqual(KeyPair expected, KeyPair actual) {
		assertNotNull(actual);
		assertNotNull(actual.getPrivate());
		assertNotNull(actual.getPublic());

		assertEquals(
				expected.getPrivate().getClass(),
				actual.getPrivate().getClass(),
				"Private key types should match");

		byte[] expectedPriv = expected.getPrivate().getEncoded();
		byte[] actualPriv = actual.getPrivate().getEncoded();
		assertEquals(expectedPriv.length, actualPriv.length, "Private key encoded length should match");

		byte[] expectedPub = expected.getPublic().getEncoded();
		byte[] actualPub = actual.getPublic().getEncoded();
		assertEquals(expectedPub.length, actualPub.length, "Public key encoded length should match");
	}
}

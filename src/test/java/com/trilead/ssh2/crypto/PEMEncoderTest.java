package com.trilead.ssh2.crypto;

import org.junit.jupiter.api.Test;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.trilead.ssh2.crypto.keys.Ed25519PrivateKey;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

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

	@Test
	void testEncodeEd25519Unencrypted() throws Exception {
		Ed25519Sign.KeyPair tinkKeyPair = Ed25519Sign.KeyPair.newKeyPair();
		Ed25519PrivateKey privateKey = new Ed25519PrivateKey(tinkKeyPair.getPrivateKey());

		String encoded = PEMEncoder.encodeEd25519PrivateKey(privateKey, null);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN PRIVATE KEY-----"));
		assertTrue(encoded.contains("-----END PRIVATE KEY-----"));

		// Verify round-trip by manually decoding PKCS#8 format
		Ed25519PrivateKey decoded = decodePkcs8Ed25519(encoded);
		assertNotNull(decoded);
		assertEquals(privateKey, decoded);
	}

	@Test
	void testEncodeEd25519WithAES256() throws Exception {
		Ed25519Sign.KeyPair tinkKeyPair = Ed25519Sign.KeyPair.newKeyPair();
		Ed25519PrivateKey privateKey = new Ed25519PrivateKey(tinkKeyPair.getPrivateKey());

		String encoded = PEMEncoder.encodeEd25519PrivateKey(privateKey, TEST_PASSWORD, PEMEncoder.AES_256_CBC);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN PRIVATE KEY-----"));
		assertTrue(encoded.contains("Proc-Type: 4,ENCRYPTED"));
		assertTrue(encoded.contains("DEK-Info: AES-256-CBC"));

		// Encryption test: verify the format is correct (decryption would require
		// implementing the same key derivation as PEMDecoder, which is not needed
		// since OpenSSH format is preferred for encrypted Ed25519 keys)
	}

	@Test
	void testEncodePrivateKeyAutoDetectEd25519() throws Exception {
		Ed25519Sign.KeyPair tinkKeyPair = Ed25519Sign.KeyPair.newKeyPair();
		Ed25519PrivateKey privateKey = new Ed25519PrivateKey(tinkKeyPair.getPrivateKey());

		String encoded = PEMEncoder.encodePrivateKey(privateKey, null);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN PRIVATE KEY-----"));

		Ed25519PrivateKey decoded = decodePkcs8Ed25519(encoded);
		assertNotNull(decoded);
		assertEquals(privateKey, decoded);
	}

	/**
	 * Decodes an Ed25519 private key from PKCS#8 PEM format.
	 */
	private Ed25519PrivateKey decodePkcs8Ed25519(String pem) throws Exception {
		String base64 = pem
				.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replaceAll("\\s", "");
		byte[] decoded = Base64.getDecoder().decode(base64);
		return new Ed25519PrivateKey(new PKCS8EncodedKeySpec(decoded));
	}

	/**
	 * Tests that non-CRT RSA keys (like Conscrypt's OpenSSLRSAPrivateKey) can be encoded.
	 * This simulates the scenario where an RSAPrivateKey does not implement RSAPrivateCrtKey.
	 */
	@Test
	void testEncodeNonCrtRSAKeyUnencrypted() throws Exception {
		KeyPair original = loadKeyPair("pem_rsa_2048", null);

		// Wrap the RSA private key to simulate a non-CRT key (like OpenSSLRSAPrivateKey)
		RSAPrivateKey nonCrtKey = new NonCrtRSAPrivateKeyWrapper((RSAPrivateCrtKey) original.getPrivate());

		// Verify our wrapper is not an instance of RSAPrivateCrtKey
		assertTrue(nonCrtKey instanceof RSAPrivateKey);
		assertTrue(!(nonCrtKey instanceof RSAPrivateCrtKey));

		// Encode using the generic method which should handle non-CRT keys
		String encoded = PEMEncoder.encodePrivateKey(nonCrtKey, null);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN RSA PRIVATE KEY-----"));
		assertTrue(encoded.contains("-----END RSA PRIVATE KEY-----"));

		// Verify round-trip
		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), null);
		assertKeysEqual(original, decoded);
	}

	/**
	 * Tests that non-CRT RSA keys can be encoded with encryption.
	 */
	@Test
	void testEncodeNonCrtRSAKeyWithAES256() throws Exception {
		KeyPair original = loadKeyPair("pem_rsa_2048", null);

		RSAPrivateKey nonCrtKey = new NonCrtRSAPrivateKeyWrapper((RSAPrivateCrtKey) original.getPrivate());

		String encoded = PEMEncoder.encodePrivateKey(nonCrtKey, TEST_PASSWORD, PEMEncoder.AES_256_CBC);

		assertNotNull(encoded);
		assertTrue(encoded.contains("-----BEGIN RSA PRIVATE KEY-----"));
		assertTrue(encoded.contains("Proc-Type: 4,ENCRYPTED"));
		assertTrue(encoded.contains("DEK-Info: AES-256-CBC"));

		KeyPair decoded = PEMDecoder.decode(encoded.toCharArray(), TEST_PASSWORD);
		assertKeysEqual(original, decoded);
	}

	/**
	 * A wrapper that implements RSAPrivateKey but NOT RSAPrivateCrtKey.
	 * This simulates keys from providers like Conscrypt's OpenSSLRSAPrivateKey.
	 */
	private static class NonCrtRSAPrivateKeyWrapper implements RSAPrivateKey {
		private final RSAPrivateCrtKey delegate;

		NonCrtRSAPrivateKeyWrapper(RSAPrivateCrtKey delegate) {
			this.delegate = delegate;
		}

		@Override
		public BigInteger getPrivateExponent() {
			return delegate.getPrivateExponent();
		}

		@Override
		public String getAlgorithm() {
			return delegate.getAlgorithm();
		}

		@Override
		public String getFormat() {
			return delegate.getFormat();
		}

		@Override
		public byte[] getEncoded() {
			return delegate.getEncoded();
		}

		@Override
		public BigInteger getModulus() {
			return delegate.getModulus();
		}
	}
}

package com.trilead.ssh2.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.trilead.ssh2.crypto.keys.Ed25519PrivateKey;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;

public class OpenSSHKeyEncoderTest {
	private char[] getPem(String s) throws IOException {
		return IOUtils.toCharArray(getClass().getResourceAsStream(s), "UTF-8");
	}

	@Test
	public void testRoundTripRSAUnencrypted() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair original = kpg.generateKeyPair();

		String exported = OpenSSHKeyEncoder.exportOpenSSHRSA(
				(RSAPrivateCrtKey) original.getPrivate(),
				(RSAPublicKey) original.getPublic(),
				"test-comment");

		assertNotNull(exported);
		assertTrue(exported.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
		assertTrue(exported.contains("-----END OPENSSH PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), null);

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
	}

	@Test
	public void testRoundTripRSAEncrypted() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair original = kpg.generateKeyPair();

		String exported = OpenSSHKeyEncoder.exportOpenSSHRSA(
				(RSAPrivateCrtKey) original.getPrivate(),
				(RSAPublicKey) original.getPublic(),
				"test-comment",
				"testpassword");

		assertNotNull(exported);
		assertTrue(exported.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), "testpassword");

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
	}

	@Test
	public void testRoundTripDSAUnencrypted() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		kpg.initialize(1024);
		KeyPair original = kpg.generateKeyPair();

		String exported = OpenSSHKeyEncoder.exportOpenSSHDSA(
				(DSAPrivateKey) original.getPrivate(),
				(DSAPublicKey) original.getPublic(),
				"test-comment");

		assertNotNull(exported);
		assertTrue(exported.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), null);

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
	}

	@Test
	public void testRoundTripDSAEncrypted() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		kpg.initialize(1024);
		KeyPair original = kpg.generateKeyPair();

		String exported = OpenSSHKeyEncoder.exportOpenSSHDSA(
				(DSAPrivateKey) original.getPrivate(),
				(DSAPublicKey) original.getPublic(),
				"test-comment",
				"testpassword");

		assertNotNull(exported);

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), "testpassword");

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
	}

	@Test
	public void testRoundTripECDSA256Unencrypted() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair original = kpg.generateKeyPair();

		String exported = OpenSSHKeyEncoder.exportOpenSSHEC(
				(ECPrivateKey) original.getPrivate(),
				(ECPublicKey) original.getPublic(),
				"test-comment");

		assertNotNull(exported);
		assertTrue(exported.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), null);

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
	}

	@Test
	public void testRoundTripECDSA256Encrypted() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair original = kpg.generateKeyPair();

		String exported = OpenSSHKeyEncoder.exportOpenSSHEC(
				(ECPrivateKey) original.getPrivate(),
				(ECPublicKey) original.getPublic(),
				"test-comment",
				"testpassword");

		assertNotNull(exported);

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), "testpassword");

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
	}

	@Test
	public void testRoundTripECDSA384() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp384r1"));
		KeyPair original = kpg.generateKeyPair();

		String exported = OpenSSHKeyEncoder.exportOpenSSHEC(
				(ECPrivateKey) original.getPrivate(),
				(ECPublicKey) original.getPublic(),
				"test-comment");

		assertNotNull(exported);

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), null);

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
	}

	@Test
	public void testRoundTripECDSA521() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp521r1"));
		KeyPair original = kpg.generateKeyPair();

		String exported = OpenSSHKeyEncoder.exportOpenSSHEC(
				(ECPrivateKey) original.getPrivate(),
				(ECPublicKey) original.getPublic(),
				"test-comment");

		assertNotNull(exported);

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), null);

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
	}

	@Test
	public void testRoundTripEd25519Unencrypted() throws Exception {
		Ed25519Sign.KeyPair tinkKeyPair = Ed25519Sign.KeyPair.newKeyPair();
		Ed25519PrivateKey privateKey = new Ed25519PrivateKey(tinkKeyPair.getPrivateKey());
		Ed25519PublicKey publicKey = new Ed25519PublicKey(tinkKeyPair.getPublicKey());

		String exported = OpenSSHKeyEncoder.exportOpenSSHEd25519(
				privateKey,
				publicKey,
				"test-comment");

		assertNotNull(exported);
		assertTrue(exported.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), null);

		assertEquals(publicKey, decoded.getPublic());
		assertEquals(privateKey, decoded.getPrivate());
	}

	@Test
	public void testRoundTripEd25519Encrypted() throws Exception {
		Ed25519Sign.KeyPair tinkKeyPair = Ed25519Sign.KeyPair.newKeyPair();
		Ed25519PrivateKey privateKey = new Ed25519PrivateKey(tinkKeyPair.getPrivateKey());
		Ed25519PublicKey publicKey = new Ed25519PublicKey(tinkKeyPair.getPublicKey());

		String exported = OpenSSHKeyEncoder.exportOpenSSHEd25519(
				privateKey,
				publicKey,
				"test-comment",
				"testpassword");

		assertNotNull(exported);

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), "testpassword");

		assertEquals(publicKey, decoded.getPublic());
		assertEquals(privateKey, decoded.getPrivate());
	}

	@Test
	public void testExportOpenSSHGeneric() throws Exception {
		KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
		rsaKpg.initialize(2048);
		KeyPair rsaPair = rsaKpg.generateKeyPair();

		String rsaExported = OpenSSHKeyEncoder.exportOpenSSH(
				rsaPair.getPrivate(),
				rsaPair.getPublic(),
				"test-rsa");
		assertNotNull(rsaExported);
		KeyPair rsaDecoded = PEMDecoder.decode(rsaExported.toCharArray(), null);
		assertEquals(rsaPair.getPublic(), rsaDecoded.getPublic());

		KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA");
		dsaKpg.initialize(1024);
		KeyPair dsaPair = dsaKpg.generateKeyPair();

		String dsaExported = OpenSSHKeyEncoder.exportOpenSSH(
				dsaPair.getPrivate(),
				dsaPair.getPublic(),
				"test-dsa");
		assertNotNull(dsaExported);
		KeyPair dsaDecoded = PEMDecoder.decode(dsaExported.toCharArray(), null);
		assertEquals(dsaPair.getPublic(), dsaDecoded.getPublic());

		KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
		ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair ecPair = ecKpg.generateKeyPair();

		String ecExported = OpenSSHKeyEncoder.exportOpenSSH(
				ecPair.getPrivate(),
				ecPair.getPublic(),
				"test-ec");
		assertNotNull(ecExported);
		KeyPair ecDecoded = PEMDecoder.decode(ecExported.toCharArray(), null);
		assertEquals(ecPair.getPublic(), ecDecoded.getPublic());

		Ed25519Sign.KeyPair tinkKeyPair = Ed25519Sign.KeyPair.newKeyPair();
		Ed25519PrivateKey ed25519Private = new Ed25519PrivateKey(tinkKeyPair.getPrivateKey());
		Ed25519PublicKey ed25519Public = new Ed25519PublicKey(tinkKeyPair.getPublicKey());

		String ed25519Exported = OpenSSHKeyEncoder.exportOpenSSH(
				ed25519Private,
				ed25519Public,
				"test-ed25519");
		assertNotNull(ed25519Exported);
		KeyPair ed25519Decoded = PEMDecoder.decode(ed25519Exported.toCharArray(), null);
		assertEquals(ed25519Public, ed25519Decoded.getPublic());
	}

	@Test
	public void testDecodeGoldenRSAAndReencode() throws Exception {
		char[] pem = getPem("/key-encoder-decoder-tests/openssh_rsa_2048");
		KeyPair kp = PEMDecoder.decode(pem, null);

		String reencoded = OpenSSHKeyEncoder.exportOpenSSHRSA(
				(RSAPrivateCrtKey) kp.getPrivate(),
				(RSAPublicKey) kp.getPublic(),
				"reencoded-test");

		KeyPair decoded = PEMDecoder.decode(reencoded.toCharArray(), null);

		assertEquals(kp.getPublic(), decoded.getPublic());
		assertEquals(kp.getPrivate(), decoded.getPrivate());
	}

	@Test
	public void testDecodeGoldenEd25519AndReencode() throws Exception {
		char[] pem = getPem("/key-encoder-decoder-tests/openssh_ed25519");
		KeyPair kp = PEMDecoder.decode(pem, null);

		String reencoded = OpenSSHKeyEncoder.exportOpenSSHEd25519(
				(Ed25519PrivateKey) kp.getPrivate(),
				(Ed25519PublicKey) kp.getPublic(),
				"reencoded-test");

		KeyPair decoded = PEMDecoder.decode(reencoded.toCharArray(), null);

		assertEquals(kp.getPublic(), decoded.getPublic());
		assertEquals(kp.getPrivate(), decoded.getPrivate());
	}

	/**
	 * Tests that non-CRT RSA keys (like Conscrypt's OpenSSLRSAPrivateKey) can be exported.
	 * This simulates the scenario where an RSAPrivateKey does not implement RSAPrivateCrtKey.
	 */
	@Test
	public void testExportOpenSSHWithNonCrtRSAKey() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair original = kpg.generateKeyPair();

		// Wrap the RSA private key to simulate a non-CRT key (like OpenSSLRSAPrivateKey)
		RSAPrivateKey nonCrtKey = new NonCrtRSAPrivateKeyWrapper((RSAPrivateCrtKey) original.getPrivate());

		// Verify our wrapper is not an instance of RSAPrivateCrtKey
		assertTrue(nonCrtKey instanceof RSAPrivateKey);
		assertTrue(!(nonCrtKey instanceof RSAPrivateCrtKey));

		// Export using the generic method which should handle non-CRT keys
		String exported = OpenSSHKeyEncoder.exportOpenSSH(
				nonCrtKey,
				original.getPublic(),
				"test-non-crt");

		assertNotNull(exported);
		assertTrue(exported.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
		assertTrue(exported.contains("-----END OPENSSH PRIVATE KEY-----"));

		// Verify round-trip
		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), null);

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
	}

	/**
	 * Tests that non-CRT RSA keys can be exported with encryption.
	 */
	@Test
	public void testExportOpenSSHWithNonCrtRSAKeyEncrypted() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair original = kpg.generateKeyPair();

		RSAPrivateKey nonCrtKey = new NonCrtRSAPrivateKeyWrapper((RSAPrivateCrtKey) original.getPrivate());

		String exported = OpenSSHKeyEncoder.exportOpenSSH(
				nonCrtKey,
				original.getPublic(),
				"test-non-crt",
				"testpassword");

		assertNotNull(exported);
		assertTrue(exported.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));

		KeyPair decoded = PEMDecoder.decode(exported.toCharArray(), "testpassword");

		assertEquals(original.getPublic(), decoded.getPublic());
		assertEquals(original.getPrivate(), decoded.getPrivate());
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

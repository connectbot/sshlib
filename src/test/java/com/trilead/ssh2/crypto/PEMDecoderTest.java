package com.trilead.ssh2.crypto;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author Michael Clarke
 */
public class PEMDecoderTest {
	private char[] getPem(String s) throws IOException {
		return IOUtils.toCharArray(getClass().getResourceAsStream(s), "UTF-8");
	}

	@Test
	public void testRsaKeyDecodingTest() throws IOException {
		KeyPair expected = PEMDecoder.decode(getPem("rsa-private-key.txt"), null);
		KeyPair actual = PEMDecoder.decode(getPem("rsa-openssh2-private-key.txt"), "password");

		assertEquals(expected.getPrivate(), actual.getPrivate());
		assertEquals(expected.getPublic(), actual.getPublic());
	}

	@Test
	public void testDsaKeyDecodingTest() throws IOException {
		KeyPair oldFormat = PEMDecoder.decode(getPem("dsa-private-key.txt"), null);
		KeyPair newFormat = PEMDecoder.decode(getPem("dsa-openssh2-private-key.txt"), null);

		assertEquals(oldFormat.getPublic(), newFormat.getPublic());
		assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
	}

	@Test
	public void testEcdsaNistp256KeyDecodingTest() throws IOException {
		KeyPair oldFormat = PEMDecoder.decode(getPem("ecdsa-nistp256-private-key.txt"), null);
		KeyPair newFormat = PEMDecoder.decode(getPem("ecdsa-nistp256-openssh2-private-key.txt"), null);

		assertEquals(oldFormat.getPublic(), newFormat.getPublic());
		assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
	}

	@Test
	public void testEcdsaNistp384KeyDecodingTest() throws IOException {
		KeyPair oldFormat = PEMDecoder.decode(getPem("ecdsa-nistp384-private-key.txt"), null);
		KeyPair newFormat = PEMDecoder.decode(getPem("ecdsa-nistp384-openssh2-private-key.txt"), null);

		assertEquals(oldFormat.getPublic(), newFormat.getPublic());
		assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
	}

	@Test
	public void testEcdsaNistp521KeyDecodingTest() throws IOException {
		KeyPair oldFormat = PEMDecoder.decode(getPem("ecdsa-nistp521-private-key.txt"), null);
		KeyPair newFormat = PEMDecoder.decode(getPem("ecdsa-nistp521-openssh2-private-key.txt"), null);

		assertEquals(oldFormat.getPublic(), newFormat.getPublic());
		assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
	}

	@Test
	public void testRSATraditionalPEMUnencrypted() throws IOException {
		KeyPair kp = PEMDecoder.decode(getPem("/key-encoder-decoder-tests/pem_rsa_2048"), null);
		assertNotNull(kp);
		assertNotNull(kp.getPrivate());
		assertNotNull(kp.getPublic());
	}

	@Test
	public void testRSATraditionalPEMAES256() throws IOException {
		KeyPair kp = PEMDecoder.decode(getPem("/key-encoder-decoder-tests/pem_rsa_2048_aes256"), "testpassword");
		assertNotNull(kp);
		assertNotNull(kp.getPrivate());
		assertNotNull(kp.getPublic());
	}

	@Test
	public void testRSATraditionalPEMAES128() throws IOException {
		KeyPair kp = PEMDecoder.decode(getPem("/key-encoder-decoder-tests/pem_rsa_2048_aes128"), "testpassword");
		assertNotNull(kp);
		assertNotNull(kp.getPrivate());
		assertNotNull(kp.getPublic());
	}

	@Test
	public void testRSATraditionalPEMDES3() throws IOException {
		KeyPair kp = PEMDecoder.decode(getPem("/key-encoder-decoder-tests/pem_rsa_2048_des3"), "testpassword");
		assertNotNull(kp);
		assertNotNull(kp.getPrivate());
		assertNotNull(kp.getPublic());
	}

	@Test
	public void testECTraditionalPEMUnencrypted() throws IOException {
		KeyPair kp = PEMDecoder.decode(getPem("/key-encoder-decoder-tests/pem_ec_256"), null);
		assertNotNull(kp);
		assertNotNull(kp.getPrivate());
		assertNotNull(kp.getPublic());
	}

	@Test
	public void testECTraditionalPEMAES256() throws IOException {
		KeyPair kp = PEMDecoder.decode(getPem("/key-encoder-decoder-tests/pem_ec_256_aes256"), "testpassword");
		assertNotNull(kp);
		assertNotNull(kp.getPrivate());
		assertNotNull(kp.getPublic());
	}

	@Test
	public void testDSATraditionalPEMAES256() throws IOException {
		KeyPair kp = PEMDecoder.decode(getPem("/key-encoder-decoder-tests/pem_dsa_aes256"), "testpassword");
		assertNotNull(kp);
		assertNotNull(kp.getPrivate());
		assertNotNull(kp.getPublic());
	}

	@Test
	public void testDSATraditionalPEMDES3() throws IOException {
		KeyPair kp = PEMDecoder.decode(getPem("/key-encoder-decoder-tests/pem_dsa_des3"), "testpassword");
		assertNotNull(kp);
		assertNotNull(kp.getPrivate());
		assertNotNull(kp.getPublic());
	}
}

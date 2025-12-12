package com.trilead.ssh2.crypto;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import com.trilead.ssh2.crypto.keys.Ed25519PrivateKey;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class OpenSSHKeyDecoderTest {
	private char[] getPem(String s) throws IOException {
		return IOUtils.toCharArray(getClass().getResourceAsStream(s), "UTF-8");
	}

	private byte[] getKeyData(String s) throws IOException {
		char[] pem = getPem(s);
		PEMStructure ps = PEMDecoder.parsePEM(pem);
		return ps.data;
	}

	@Test
	public void testDecodeRSAUnencrypted() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_rsa_2048");
		KeyPair kp = OpenSSHKeyDecoder.decode(data, null);

		assertNotNull(kp);
		assertTrue(kp.getPrivate() instanceof RSAPrivateCrtKey);
		assertTrue(kp.getPublic() instanceof RSAPublicKey);

		RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kp.getPrivate();
		RSAPublicKey pub = (RSAPublicKey) kp.getPublic();

		assertEquals(priv.getModulus(), pub.getModulus());
		assertEquals(priv.getPublicExponent(), pub.getPublicExponent());
	}

	@Test
	public void testDecodeRSAEncrypted() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_rsa_2048_encrypted");
		KeyPair kp = OpenSSHKeyDecoder.decode(data, "testpassword");

		assertNotNull(kp);
		assertTrue(kp.getPrivate() instanceof RSAPrivateCrtKey);
		assertTrue(kp.getPublic() instanceof RSAPublicKey);
	}

	@Test
	public void testDecodeRSAEncryptedWrongPassword() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_rsa_2048_encrypted");
		assertThrows(IOException.class, () -> OpenSSHKeyDecoder.decode(data, "wrongpassword"));
	}

	@Test
	public void testDecodeRSAEncryptedMissingPassword() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_rsa_2048_encrypted");
		assertThrows(IOException.class, () -> OpenSSHKeyDecoder.decode(data, null));
	}

	@Test
	public void testDecodeECDSA256Unencrypted() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_ecdsa_256");
		KeyPair kp = OpenSSHKeyDecoder.decode(data, null);

		assertNotNull(kp);
		assertTrue(kp.getPrivate() instanceof ECPrivateKey);
		assertTrue(kp.getPublic() instanceof ECPublicKey);

		ECPublicKey pub = (ECPublicKey) kp.getPublic();
		assertEquals(256, pub.getParams().getCurve().getField().getFieldSize());
	}

	@Test
	public void testDecodeECDSA256Encrypted() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_ecdsa_256_encrypted");
		KeyPair kp = OpenSSHKeyDecoder.decode(data, "testpassword");

		assertNotNull(kp);
		assertTrue(kp.getPrivate() instanceof ECPrivateKey);
		assertTrue(kp.getPublic() instanceof ECPublicKey);

		ECPublicKey pub = (ECPublicKey) kp.getPublic();
		assertEquals(256, pub.getParams().getCurve().getField().getFieldSize());
	}

	@Test
	public void testDecodeECDSA384() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_ecdsa_384");
		KeyPair kp = OpenSSHKeyDecoder.decode(data, null);

		assertNotNull(kp);
		assertTrue(kp.getPublic() instanceof ECPublicKey);

		ECPublicKey pub = (ECPublicKey) kp.getPublic();
		assertEquals(384, pub.getParams().getCurve().getField().getFieldSize());
	}

	@Test
	public void testDecodeECDSA521() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_ecdsa_521");
		KeyPair kp = OpenSSHKeyDecoder.decode(data, null);

		assertNotNull(kp);
		assertTrue(kp.getPublic() instanceof ECPublicKey);

		ECPublicKey pub = (ECPublicKey) kp.getPublic();
		assertEquals(521, pub.getParams().getCurve().getField().getFieldSize());
	}

	@Test
	public void testDecodeEd25519Unencrypted() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_ed25519");
		KeyPair kp = OpenSSHKeyDecoder.decode(data, null);

		assertNotNull(kp);
		assertTrue(kp.getPrivate() instanceof Ed25519PrivateKey);
		assertTrue(kp.getPublic() instanceof Ed25519PublicKey);
	}

	@Test
	public void testDecodeEd25519Encrypted() throws IOException {
		byte[] data = getKeyData("/key-encoder-decoder-tests/openssh_ed25519_encrypted");
		KeyPair kp = OpenSSHKeyDecoder.decode(data, "testpassword");

		assertNotNull(kp);
		assertTrue(kp.getPrivate() instanceof Ed25519PrivateKey);
		assertTrue(kp.getPublic() instanceof Ed25519PublicKey);
	}

	@Test
	public void testIsEncryptedRSA() throws IOException {
		byte[] dataUnencrypted = getKeyData("/key-encoder-decoder-tests/openssh_rsa_2048");
		assertFalse(OpenSSHKeyDecoder.isEncrypted(dataUnencrypted));

		byte[] dataEncrypted = getKeyData("/key-encoder-decoder-tests/openssh_rsa_2048_encrypted");
		assertTrue(OpenSSHKeyDecoder.isEncrypted(dataEncrypted));
	}

	@Test
	public void testIsEncryptedEd25519() throws IOException {
		byte[] dataUnencrypted = getKeyData("/key-encoder-decoder-tests/openssh_ed25519");
		assertFalse(OpenSSHKeyDecoder.isEncrypted(dataUnencrypted));

		byte[] dataEncrypted = getKeyData("/key-encoder-decoder-tests/openssh_ed25519_encrypted");
		assertTrue(OpenSSHKeyDecoder.isEncrypted(dataEncrypted));
	}
}

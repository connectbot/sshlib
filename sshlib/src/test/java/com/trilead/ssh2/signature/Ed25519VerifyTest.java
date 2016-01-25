package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.key.Ed25519PrivateKey;
import com.trilead.ssh2.crypto.key.Ed25519PublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;

import static org.junit.Assert.*;

/**
 * Created by kenny on 1/24/16.
 */
public class Ed25519VerifyTest {
	/* Test vectors from draft-josefsson-eddsa-ed25519-03 */
	private static final byte[] SECRET_KEY = toByteArray("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
	private static final byte[] PUBLIC_KEY = toByteArray("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
	private static final byte[] MESSAGE = toByteArray("616263");
	private static final byte[] SIGNATURE = toByteArray("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");

	private static byte[] toByteArray(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}

	@Test
	public void verifies() throws Exception {
		Ed25519PublicKey pubKey = Ed25519PublicKey.getInstance(PUBLIC_KEY);
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		assertTrue(Ed25519Verify.verifySignature(md.digest(MESSAGE), SIGNATURE, pubKey));
	}

	@Test
	public void noVerificationForInvalidData() throws Exception {
		Ed25519PublicKey pubKey = Ed25519PublicKey.getInstance(PUBLIC_KEY);
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		assertFalse(Ed25519Verify.verifySignature(md.digest(new byte[1]), SIGNATURE, pubKey));
	}

	@Test
	public void signs() throws Exception {
		Ed25519PrivateKey privKey = Ed25519PrivateKey.getInstance(SECRET_KEY);
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		assertArrayEquals(SIGNATURE, Ed25519Verify.generateSignature(md.digest(MESSAGE), privKey));
	}

	@Test
	public void publicKeyCalculatedCorrectly() throws Exception {
		EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
		EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(SECRET_KEY, spec);
		byte[] pubKeyBytes = privKeySpec.getA().toByteArray();
		assertArrayEquals(PUBLIC_KEY, pubKeyBytes);
	}

	@Test
	public void loopbackSuccess() throws Exception {
		Ed25519PrivateKey privKey = Ed25519PrivateKey.getInstance(SECRET_KEY);
		Ed25519PublicKey pubKey = Ed25519PublicKey.getInstance(PUBLIC_KEY);
		MessageDigest md = MessageDigest.getInstance("SHA-512");

		byte[] message = new byte[] { (byte) 0xA5, (byte) 0x5A };
		byte[] digest = md.digest(message);

		byte[] sig = Ed25519Verify.generateSignature(digest, privKey);
		assertTrue(Ed25519Verify.verifySignature(digest, sig, pubKey));
	}
}
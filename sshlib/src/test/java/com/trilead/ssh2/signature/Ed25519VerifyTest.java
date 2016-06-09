package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.PEMDecoder;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
	private EdDSANamedCurveSpec spec;

	private static byte[] toByteArray(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}

	@Before
	public void setupSpec() {
		this.spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
	}

	@Test
	public void verifies() throws Exception {
		EdDSAPublicKey pubKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(PUBLIC_KEY, spec));
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		assertTrue(Ed25519Verify.verifySignature(md.digest(MESSAGE), SIGNATURE, pubKey));
	}

	@Test
	public void noVerificationForInvalidData() throws Exception {
		EdDSAPublicKey pubKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(PUBLIC_KEY, spec));
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		assertFalse(Ed25519Verify.verifySignature(md.digest(new byte[1]), SIGNATURE, pubKey));
	}

	@Test
	public void signs() throws Exception {
		EdDSAPrivateKey privKey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(SECRET_KEY, spec));
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		assertArrayEquals(SIGNATURE, Ed25519Verify.generateSignature(md.digest(MESSAGE), privKey));
	}

	@Test
	public void publicKeyCalculatedCorrectly() throws Exception {
		EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(SECRET_KEY, spec);
		byte[] pubKeyBytes = privKeySpec.getA().toByteArray();
		assertArrayEquals(PUBLIC_KEY, pubKeyBytes);
	}

	@Test
	public void decodeEncodedSuccess() throws Exception {
		EdDSAPrivateKey privKey1 = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(SECRET_KEY, spec));
		EdDSAPrivateKey privKey2 = new EdDSAPrivateKey(new PKCS8EncodedKeySpec(privKey1.getEncoded()));

		EdDSAPublicKey pubKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(PUBLIC_KEY, spec));
		MessageDigest md = MessageDigest.getInstance("SHA-512");

		byte[] message = new byte[] { (byte) 0xA5, (byte) 0x5A };
		byte[] digest = md.digest(message);

		byte[] sig1 = Ed25519Verify.generateSignature(digest, privKey1);
		assertTrue(Ed25519Verify.verifySignature(digest, sig1, pubKey));

		byte[] sig2 = Ed25519Verify.generateSignature(digest, privKey1);
		assertTrue(Ed25519Verify.verifySignature(digest, sig2, pubKey));
	}

	@Test
	public void loopbackSuccess() throws Exception {
		EdDSAPrivateKey privKey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(SECRET_KEY, spec));
		EdDSAPublicKey pubKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(PUBLIC_KEY, spec));
		MessageDigest md = MessageDigest.getInstance("SHA-512");

		byte[] message = new byte[] { (byte) 0xA5, (byte) 0x5A };
		byte[] digest = md.digest(message);

		byte[] sig = Ed25519Verify.generateSignature(digest, privKey);
		assertTrue(Ed25519Verify.verifySignature(digest, sig, pubKey));
	}

	@Test
	public void privateKeyDecodeSuccess() throws Exception {
		char[] pemKey = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
			"QyNTUxOQAAACDd4c82N3RMipI3LlmjN4BBrJv8d6RhjF56hdwpH0mBEwAAAKjXjeu7143r\n" +
			"uwAAAAtzc2gtZWQyNTUxOQAAACDd4c82N3RMipI3LlmjN4BBrJv8d6RhjF56hdwpH0mBEw\n" +
			"AAAEADrhyPk5eQ1m2ug2lkKnDLrfxnzolJjMpDSRomN1TWwt3hzzY3dEyKkjcuWaM3gEGs\n" +
			"m/x3pGGMXnqF3CkfSYETAAAAH2tyb290QGtyb290Lm10di5jb3JwLmdvb2dsZS5jb20BAg\n" +
			"MEBQY=\n" +
			"-----END OPENSSH PRIVATE KEY-----\n").toCharArray();
		PEMDecoder.parsePEM(pemKey);
	}

}

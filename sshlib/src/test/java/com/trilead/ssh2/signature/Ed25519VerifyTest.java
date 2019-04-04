package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.crypto.PEMDecoder;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by kenny on 1/24/16.
 */
public class Ed25519VerifyTest {
	/* Test vectors from draft-josefsson-eddsa-ed25519-03 */
	private static final byte[] SECRET_KEY = toByteArray("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
	private static final byte[] PUBLIC_KEY = toByteArray("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
	private static final byte[] MESSAGE = toByteArray("616263");
	private static final byte[] SIGNATURE = toByteArray("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");

	private static final byte[] SSH_KAT_MESSAGE = toByteArray("4885f67437486e61");
	private static final byte[] SSH_KAT_SIGNATURE = toByteArray("0000000b7373682d656432353531390000004022e82017bd03b6d3ac969b3c519e8f25af0ec058e9c0d1263a93ac010be7270c6a4cccbfb3ca7dbd6ee993e2764e95c18b5a620a1794501f85a4d8a7946af106");
	private static final char[] SSH_KAT_PRIVATE = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
		"QyNTUxOQAAACBThupGO0X+FLQhbz8CoKPwc7V3JNsQuGtlsgN+F7SMGQAAAJjnj4Ao54+A\n" +
		"KAAAAAtzc2gtZWQyNTUxOQAAACBThupGO0X+FLQhbz8CoKPwc7V3JNsQuGtlsgN+F7SMGQ\n" +
		"AAAED3KgoDbjR54V7bdNpfKlQY5m20UK1QaHytkCR+6rZEDFOG6kY7Rf4UtCFvPwKgo/Bz\n" +
		"tXck2xC4a2WyA34XtIwZAAAAE0VEMjU1MTkgdGVzdCBrZXkgIzEBAg==\n" +
		"-----END OPENSSH PRIVATE KEY-----").toCharArray();
	private static final byte[] SSH_KAT_ED25519_PK = toByteArray("5386ea463b45fe14b4216f3f02a0a3f073b57724db10b86b65b2037e17b48c19");
	private static final byte[] SSH_KAT_ED25519_SK = toByteArray("f72a0a036e3479e15edb74da5f2a5418e66db450ad50687cad90247eeab6440c");
        // There is actually another 32 bytes in the key, but it's not used.
        // 5386ea463b45fe14b4216f3f02a0a3f073b57724db10b86b65b2037e17b48c19

	private EdDSANamedCurveSpec spec;

	private static byte[] toByteArray(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int hexIndex = i * 2;
			int hexDigit = Integer.parseInt(s.substring(hexIndex, hexIndex + 2), 16);
			b[i] = (byte) hexDigit;
		}
		return b;
	}

	@Before
	public void setupSpec() {
		this.spec = EdDSANamedCurveTable.getByName(Ed25519Verify.ED25519_CURVE_NAME);
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
	public void publicKeyCalculatedCorrectly() {
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

	private static final char[] SSH_PRIVATE_KEY = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
		"QyNTUxOQAAACDfbA2PEVsvCpsNiLURs0nifELRIq5CEhDFQ+4i10W1cQAAAKhBsisTQbIr\n" +
		"EwAAAAtzc2gtZWQyNTUxOQAAACDfbA2PEVsvCpsNiLURs0nifELRIq5CEhDFQ+4i10W1cQ\n" +
		"AAAEAIbXzBNVlb+eO63rEGkFFLzIu9IfdiU7Q+fBgcD14R999sDY8RWy8Kmw2ItRGzSeJ8\n" +
		"QtEirkISEMVD7iLXRbVxAAAAH2tyb290QGtyb290Lm10di5jb3JwLmdvb2dsZS5jb20BAg\n" +
		"MEBQY=\n" +
		"-----END OPENSSH PRIVATE KEY-----\n").toCharArray();
	private static final String SSH_PUBLIC_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIN9sDY8RWy8Kmw2ItRGzSeJ8QtEirkISEMVD7iLXRbVx";

	@Test
	public void privateKeyDecodeSuccess() throws Exception {
		KeyPair pair = PEMDecoder.decode(SSH_PRIVATE_KEY, null);
	}

	private EdDSAPublicKey getTestPubKey() throws IOException {
		return (EdDSAPublicKey) PEMDecoder.decode(SSH_PRIVATE_KEY, null).getPublic();
	}

	private byte[] getTestPubKeyBytes() throws Exception {
		return Base64.decode(SSH_PUBLIC_KEY.toCharArray());
	}

	@Test
	public void publicKeyEncodeDecodeSuccess() throws Exception {
		assertArrayEquals(getTestPubKeyBytes(), Ed25519Verify.encodeSSHEd25519PublicKey(getTestPubKey()));
	}

	@Test
	public void publicKeyDecodeSuccess() throws Exception {
		assertArrayEquals(getTestPubKey().getEncoded(), Ed25519Verify.decodeSSHEd25519PublicKey(getTestPubKeyBytes()).getEncoded());
	}

	@Test(expected = IOException.class)
	public void publicKeyDecode_ExcessPadding_Failure() throws Exception {
		byte[] validKey = getTestPubKeyBytes();
		byte[] invalidKey = new byte[validKey.length + 1];
		System.arraycopy(validKey, 0, invalidKey, 0, validKey.length);
		Ed25519Verify.decodeSSHEd25519PublicKey(invalidKey);
	}

	@Test
	public void opensshVectorVerifies() throws Exception {
		KeyPair pair = PEMDecoder.decode(SSH_KAT_PRIVATE, null);
		assertTrue(Ed25519Verify.verifySignature(SSH_KAT_MESSAGE,
				Ed25519Verify.decodeSSHEd25519Signature(SSH_KAT_SIGNATURE),
				(EdDSAPublicKey) pair.getPublic()));
	}

	@Test
	public void opensshPrivateDecodesCorrectly() throws Exception {
		KeyPair pair = PEMDecoder.decode(SSH_KAT_PRIVATE, null);
		assertArrayEquals(SSH_KAT_ED25519_SK, ((EdDSAPrivateKey) pair.getPrivate()).getSeed());
		assertArrayEquals(SSH_KAT_ED25519_PK, ((EdDSAPublicKey) pair.getPublic()).getAbyte());
	}

	@Test
	public void opensshVectorSigns() throws Exception {
		KeyPair pair = PEMDecoder.decode(SSH_KAT_PRIVATE, null);
		byte[] sig = Ed25519Verify.generateSignature(SSH_KAT_MESSAGE, (EdDSAPrivateKey) pair.getPrivate());
		byte[] encoded = Ed25519Verify.encodeSSHEd25519Signature(sig);
		assertArrayEquals(SSH_KAT_SIGNATURE, Ed25519Verify.encodeSSHEd25519Signature(sig));
	}
}

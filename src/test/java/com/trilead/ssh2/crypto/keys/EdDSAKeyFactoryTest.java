package com.trilead.ssh2.crypto.keys;

import org.junit.Test;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class EdDSAKeyFactoryTest {
	private static final byte[] PRIVATE = toByteArray("302e020100300506032b657004220420f72a0a036e3479e15edb74da5f2a5418e66db450ad50687cad90247eeab6440c");
	private static final byte[] PUBLIC = toByteArray("302a300506032b65700321005386ea463b45fe14b4216f3f02a0a3f073b57724db10b86b65b2037e17b48c19");
	private static final byte[] KAT_ED25519_PRIV = toByteArray("f72a0a036e3479e15edb74da5f2a5418e66db450ad50687cad90247eeab6440c");
	private static final byte[] KAT_ED25519_PUB = toByteArray("5386ea463b45fe14b4216f3f02a0a3f073b57724db10b86b65b2037e17b48c19");

	private static byte[] toByteArray(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int hexIndex = i * 2;
			int hexDigit = Integer.parseInt(s.substring(hexIndex, hexIndex + 2), 16);
			b[i] = (byte) hexDigit;
		}
		return b;
	}

	@Test
	public void generatesPrivateKey() throws Exception {
		EdDSAProvider p = new EdDSAProvider();
		KeyFactory kf = KeyFactory.getInstance("EdDSA", p);
		EdDSAPrivateKey pk = (EdDSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(PRIVATE));
		assertThat(pk.getSeed(), is(KAT_ED25519_PRIV));
	}


	@Test
	public void generatesPublicKey() throws Exception {
		EdDSAProvider p = new EdDSAProvider();
		KeyFactory kf = KeyFactory.getInstance("EdDSA", p);
		EdDSAPublicKey pub = (EdDSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(PUBLIC));
		assertThat(pub.getAbyte(), is(KAT_ED25519_PUB));
	}
}

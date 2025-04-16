package com.trilead.ssh2.crypto.keys;

import org.junit.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;

public class Ed25519KeyFactoryTest {
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
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);
		Ed25519PrivateKey pk = (Ed25519PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(PRIVATE));
		assertThat(pk.getSeed(), is(KAT_ED25519_PRIV));
	}


	@Test
	public void generatesPublicKey() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);
		Ed25519PublicKey pub = (Ed25519PublicKey) kf.generatePublic(new X509EncodedKeySpec(PUBLIC));
		assertThat(pub.getAbyte(), is(KAT_ED25519_PUB));
	}

	@Test
	public void translatesNativeJDKKeys() throws Exception {
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("EdDSA");
		} catch (NoSuchAlgorithmException e) {
			// Skip test if EdDSA is not supported by the JDK
			System.err.println("Skipping translatesNativeJDKKeys test: EdDSA not supported by this JDK");
			return;
		}

		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey nativePubKey = keyPair.getPublic();
		PrivateKey nativePrivKey = keyPair.getPrivate();

		Ed25519KeyFactory keyFactorySpi = new Ed25519KeyFactory();

		// Translate Public Key
		PublicKey translatedPubKey = (PublicKey) keyFactorySpi.engineTranslateKey(nativePubKey);
		assertThat(translatedPubKey.getAlgorithm(), is("EdDSA"));
		assertThat(translatedPubKey.getFormat(), is("X.509"));
		assertArrayEquals(nativePubKey.getEncoded(), translatedPubKey.getEncoded());
		assertThat(((Ed25519PublicKey) translatedPubKey).getAbyte(), is(((Ed25519PublicKey) keyFactorySpi
				.engineGeneratePublic(new X509EncodedKeySpec(nativePubKey.getEncoded()))).getAbyte()));

		// Translate Private Key
		PrivateKey translatedPrivKey = (PrivateKey) keyFactorySpi.engineTranslateKey(nativePrivKey);
		assertThat(translatedPrivKey.getAlgorithm(), is("EdDSA"));
		assertThat(translatedPrivKey.getFormat(), is("PKCS#8"));
		assertArrayEquals(nativePrivKey.getEncoded(), translatedPrivKey.getEncoded());
		assertThat(((Ed25519PrivateKey) translatedPrivKey).getSeed(), is(((Ed25519PrivateKey) keyFactorySpi
				.engineGeneratePrivate(new PKCS8EncodedKeySpec(nativePrivKey.getEncoded()))).getSeed()));
	}
}

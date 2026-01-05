package com.trilead.ssh2.crypto.keys;

import org.junit.jupiter.api.Test;

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
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class Ed25519KeyFactoryTest {
	private static final byte[] PRIVATE = toByteArray("302e020100300506032b657004220420f72a0a036e3479e15edb74da5f2a5418e66db450ad50687cad90247eeab6440c");
	private static final byte[] PUBLIC = toByteArray("302a300506032b65700321005386ea463b45fe14b4216f3f02a0a3f073b57724db10b86b65b2037e17b48c19");
	private static final byte[] KAT_ED25519_PRIV = toByteArray("f72a0a036e3479e15edb74da5f2a5418e66db450ad50687cad90247eeab6440c");
	private static final byte[] KAT_ED25519_PUB = toByteArray("5386ea463b45fe14b4216f3f02a0a3f073b57724db10b86b65b2037e17b48c19");

	private static final byte[] OPENSSL_PRIVATE = toByteArray("302e020100300506032b657004220420afd211ae1c8a61e212ddfc5cc59949f6c37ef2f683772c14088a2f8e7b54baf7");
	private static final byte[] OPENSSL_PUBLIC = toByteArray("302a300506032b657003210006e59c37d4b0567863eb56397f7a2cfb78ae26a53dbd2206d83fb2c9cf1cbaea");
	private static final byte[] OPENSSL_ED25519_PRIV = toByteArray("afd211ae1c8a61e212ddfc5cc59949f6c37ef2f683772c14088a2f8e7b54baf7");
	private static final byte[] OPENSSL_ED25519_PUB = toByteArray("06e59c37d4b0567863eb56397f7a2cfb78ae26a53dbd2206d83fb2c9cf1cbaea");

	// Generated with library version before commit 55e3ec98 (commit ce1cc53)
	private static final byte[] OLD_LIB_PRIVATE = toByteArray("302e020100300506032b6570042204208fbad2fd15d27ca0a7b13c877d31b48e4a53ea55d9afc795f49696a50c389a77");
	private static final byte[] OLD_LIB_PUBLIC = toByteArray("302a300506032b6570032100b018a2d34b081be789c9f1af3896dcc14f7c963d3ce9dd38f7d805865f09ca88");
	private static final byte[] OLD_LIB_ED25519_PRIV = toByteArray("8fbad2fd15d27ca0a7b13c877d31b48e4a53ea55d9afc795f49696a50c389a77");
	private static final byte[] OLD_LIB_ED25519_PUB = toByteArray("b018a2d34b081be789c9f1af3896dcc14f7c963d3ce9dd38f7d805865f09ca88");

	// Legacy RAW format from commits f01a8b9 to 91bf5d0 (May-July 2020)
	// Before 91bf5d0, getEncoded() returned just the raw 32-byte seed with format "RAW"
	// This tests backward compatibility for keys stored during that 2-month period
	private static final byte[] LEGACY_RAW_PRIVATE = toByteArray("afd211ae1c8a61e212ddfc5cc59949f6c37ef2f683772c14088a2f8e7b54baf7");
	private static final byte[] LEGACY_RAW_PUBLIC = toByteArray("06e59c37d4b0567863eb56397f7a2cfb78ae26a53dbd2206d83fb2c9cf1cbaea");

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

	@Test
	public void decodesOpenSSLGeneratedPrivateKey() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);
		Ed25519PrivateKey pk = (Ed25519PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(OPENSSL_PRIVATE));
		assertThat(pk.getSeed(), is(OPENSSL_ED25519_PRIV));
	}

	@Test
	public void decodesOpenSSLGeneratedPublicKey() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);
		Ed25519PublicKey pub = (Ed25519PublicKey) kf.generatePublic(new X509EncodedKeySpec(OPENSSL_PUBLIC));
		assertThat(pub.getAbyte(), is(OPENSSL_ED25519_PUB));
	}

	@Test
	public void openSSLKeyRoundTrip() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);

		Ed25519PrivateKey privateKey = (Ed25519PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(OPENSSL_PRIVATE));
		Ed25519PublicKey publicKey = (Ed25519PublicKey) kf.generatePublic(new X509EncodedKeySpec(OPENSSL_PUBLIC));

		byte[] reEncodedPrivate = privateKey.getEncoded();
		byte[] reEncodedPublic = publicKey.getEncoded();

		assertArrayEquals(OPENSSL_PRIVATE, reEncodedPrivate);
		assertArrayEquals(OPENSSL_PUBLIC, reEncodedPublic);

		Ed25519PrivateKey privateKey2 = (Ed25519PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(reEncodedPrivate));
		Ed25519PublicKey publicKey2 = (Ed25519PublicKey) kf.generatePublic(new X509EncodedKeySpec(reEncodedPublic));

		assertThat(privateKey2.getSeed(), is(OPENSSL_ED25519_PRIV));
		assertThat(publicKey2.getAbyte(), is(OPENSSL_ED25519_PUB));
	}

	@Test
	public void decodesOldLibraryGeneratedPrivateKey() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);
		Ed25519PrivateKey pk = (Ed25519PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(OLD_LIB_PRIVATE));
		assertThat(pk.getSeed(), is(OLD_LIB_ED25519_PRIV));
	}

	@Test
	public void decodesOldLibraryGeneratedPublicKey() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);
		Ed25519PublicKey pub = (Ed25519PublicKey) kf.generatePublic(new X509EncodedKeySpec(OLD_LIB_PUBLIC));
		assertThat(pub.getAbyte(), is(OLD_LIB_ED25519_PUB));
	}

	@Test
	public void oldLibraryKeyRoundTrip() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);

		Ed25519PrivateKey privateKey = (Ed25519PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(OLD_LIB_PRIVATE));
		Ed25519PublicKey publicKey = (Ed25519PublicKey) kf.generatePublic(new X509EncodedKeySpec(OLD_LIB_PUBLIC));

		byte[] reEncodedPrivate = privateKey.getEncoded();
		byte[] reEncodedPublic = publicKey.getEncoded();

		assertArrayEquals(OLD_LIB_PRIVATE, reEncodedPrivate);
		assertArrayEquals(OLD_LIB_PUBLIC, reEncodedPublic);

		Ed25519PrivateKey privateKey2 = (Ed25519PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(reEncodedPrivate));
		Ed25519PublicKey publicKey2 = (Ed25519PublicKey) kf.generatePublic(new X509EncodedKeySpec(reEncodedPublic));

		assertThat(privateKey2.getSeed(), is(OLD_LIB_ED25519_PRIV));
		assertThat(publicKey2.getAbyte(), is(OLD_LIB_ED25519_PUB));
	}

	@Test
	public void decodesLegacyRawFormatPrivateKey() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);

		Ed25519PrivateKey pk = (Ed25519PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(LEGACY_RAW_PRIVATE));

		assertThat(pk.getSeed(), is(LEGACY_RAW_PRIVATE));

		byte[] reEncoded = pk.getEncoded();
		assertThat(reEncoded.length, is(48));
	}

	@Test
	public void decodesLegacyRawFormatPublicKey() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyFactory kf = KeyFactory.getInstance("Ed25519", p);

		Ed25519PublicKey pub = (Ed25519PublicKey) kf.generatePublic(new X509EncodedKeySpec(LEGACY_RAW_PUBLIC));

		assertThat(pub.getAbyte(), is(LEGACY_RAW_PUBLIC));

		byte[] reEncoded = pub.getEncoded();
		assertThat(reEncoded.length, is(44));
	}

}

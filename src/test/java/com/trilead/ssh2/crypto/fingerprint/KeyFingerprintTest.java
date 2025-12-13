package com.trilead.ssh2.crypto.fingerprint;

import com.trilead.ssh2.crypto.PEMDecoder;
import com.trilead.ssh2.crypto.PublicKeyUtils;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyFingerprintTest {

	private static final String TEST_RESOURCES = "src/test/resources/key-encoder-decoder-tests/";

	@Test
	void testSHA256FingerprintRSA() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_rsa_2048");
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());

		String fingerprint = KeyFingerprint.createSHA256Fingerprint(blob);

		assertEquals("SHA256:kKbdmK+Vqeu/XRnlPNOMuAgG7cIeii3bYsZTY6tY1xM", fingerprint);
	}

	@Test
	void testSHA256FingerprintEd25519() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_ed25519");
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());

		String fingerprint = KeyFingerprint.createSHA256Fingerprint(blob);

		assertEquals("SHA256:ipFSnJE3W8hvAVsyIO2+4M/MZDrzASdMF272NE7LJMY", fingerprint);
	}

	@Test
	void testSHA256FingerprintHexRSA() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_rsa_2048");
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());

		String fingerprint = KeyFingerprint.createSHA256FingerprintHex(blob);

		assertTrue(fingerprint.startsWith("SHA256:"));
		String hexPart = fingerprint.substring(7);
		String[] parts = hexPart.split(":");
		assertEquals(32, parts.length);
	}

	@Test
	void testMD5FingerprintRSA() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_rsa_2048");
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());

		String fingerprint = KeyFingerprint.createMD5Fingerprint(blob);

		assertEquals("7b:7f:ef:47:43:38:05:39:1d:23:be:1f:f9:8a:cc:a3", fingerprint);
	}

	@Test
	void testBubblebableFingerprintRSA() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_rsa_2048");
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());

		String fingerprint = KeyFingerprint.createBubblebabbleFingerprint(blob);

		assertEquals("xitiz-ritah-gykez-movir-disum-zibid-tobin-kahem-nesot-kanem-kexux", fingerprint);
	}

	@Test
	void testRandomArtContentRSA() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_rsa_2048");
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(keyPair.getPublic());

		String randomart = KeyFingerprint.createRandomArt(blob, "RSA", 2048);

		String expected = "+---[RSA 2048]----+\n" +
				"|                 |\n" +
				"|       o         |\n" +
				"|      = .     .  |\n" +
				"|     = B     = + |\n" +
				"|    . E S   o * o|\n" +
				"|   o++ * + . + o |\n" +
				"| .+o+o+ = . +    |\n" +
				"| o*=.  = . .     |\n" +
				"|.oo+..=oo..      |\n" +
				"+----[SHA256]-----+";

		assertEquals(expected, randomart);
	}

	@Test
	void testRandomArtContentRSAFromPublicKey() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_rsa_2048");

		String randomart = KeyFingerprint.createRandomArt(keyPair.getPublic());

		String expected = "+---[RSA 2048]----+\n" +
				"|                 |\n" +
				"|       o         |\n" +
				"|      = .     .  |\n" +
				"|     = B     = + |\n" +
				"|    . E S   o * o|\n" +
				"|   o++ * + . + o |\n" +
				"| .+o+o+ = . +    |\n" +
				"| o*=.  = . .     |\n" +
				"|.oo+..=oo..      |\n" +
				"+----[SHA256]-----+";

		assertEquals(expected, randomart);
	}

	@Test
	void testSHA256FingerprintFromPublicKey() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_rsa_2048");

		String fingerprint = KeyFingerprint.createSHA256Fingerprint(keyPair.getPublic());

		assertEquals("SHA256:kKbdmK+Vqeu/XRnlPNOMuAgG7cIeii3bYsZTY6tY1xM", fingerprint);
	}

	@Test
	void testMD5FingerprintFromPublicKey() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_rsa_2048");

		String fingerprint = KeyFingerprint.createMD5Fingerprint(keyPair.getPublic());

		assertEquals("7b:7f:ef:47:43:38:05:39:1d:23:be:1f:f9:8a:cc:a3", fingerprint);
	}

	@Test
	void testBubblebabbleFingerprintFromPublicKey() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_rsa_2048");

		String fingerprint = KeyFingerprint.createBubblebabbleFingerprint(keyPair.getPublic());

		assertEquals("xitiz-ritah-gykez-movir-disum-zibid-tobin-kahem-nesot-kanem-kexux", fingerprint);
	}

	@Test
	void testRandomArtContentEd25519() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_ed25519");

		String randomart = KeyFingerprint.createRandomArt(keyPair.getPublic());

		String expected = "+--[ED25519 256]--+\n" +
				"|  ..+++o.        |\n" +
				"|   =o+==o        |\n" +
				"|  ..E.*= .       |\n" +
				"| o *.X.oo        |\n" +
				"|  =.+ =.S        |\n" +
				"|  .=.o .         |\n" +
				"| . .=..          |\n" +
				"|  +B..           |\n" +
				"|  .=*            |\n" +
				"+----[SHA256]-----+";

		assertEquals(expected, randomart);
	}

	@Test
	void testRandomArtContentECDSA256() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_ecdsa_256");

		String randomart = KeyFingerprint.createRandomArt(keyPair.getPublic());

		String expected = "+---[ECDSA 256]---+\n" +
				"|*+o.+            |\n" +
				"|. oB o o  .      |\n" +
				"|..  * = o*       |\n" +
				"|.   .o B= =      |\n" +
				"| . o .++S= .     |\n" +
				"|  . ....+o+..    |\n" +
				"|      ..==E..    |\n" +
				"|       =.ooo     |\n" +
				"|      ..o.o      |\n" +
				"+----[SHA256]-----+";

		assertEquals(expected, randomart);
	}

	@Test
	void testRandomArtContentECDSA384() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_ecdsa_384");

		String randomart = KeyFingerprint.createRandomArt(keyPair.getPublic());

		String expected = "+---[ECDSA 384]---+\n" +
				"|        ..       |\n" +
				"|       . +.o .   |\n" +
				"|        O Xoo    |\n" +
				"|     .E* @ ==.   |\n" +
				"|     oBoS *=.+   |\n" +
				"|    += *.ooo+ o  |\n" +
				"|   ..oB... o.    |\n" +
				"|     .oo         |\n" +
				"|                 |\n" +
				"+----[SHA256]-----+";

		assertEquals(expected, randomart);
	}

	@Test
	void testRandomArtContentECDSA521() throws Exception {
		KeyPair keyPair = loadKeyPair("openssh_ecdsa_521");

		String randomart = KeyFingerprint.createRandomArt(keyPair.getPublic());

		String expected = "+---[ECDSA 521]---+\n" +
				"|    .+.o  oB#Xo..|\n" +
				"|    . B + =B*o.E.|\n" +
				"|     * O B.  o.  |\n" +
				"|      B +.. +    |\n" +
				"|     . +S  o .   |\n" +
				"|      o .   +    |\n" +
				"|     .     o o   |\n" +
				"|            +    |\n" +
				"|             .   |\n" +
				"+----[SHA256]-----+";

		assertEquals(expected, randomart);
	}

	private KeyPair loadKeyPair(String name) throws Exception {
		String path = TEST_RESOURCES + name;
		byte[] keyData = Files.readAllBytes(Paths.get(path));
		String keyString = new String(keyData, "UTF-8");
		return PEMDecoder.decode(keyString.toCharArray(), null);
	}
}

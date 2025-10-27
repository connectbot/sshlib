package com.trilead.ssh2.crypto.cipher;

import org.junit.jupiter.api.Test;

/**
 * Testing composed AES-CBC mode.
 * <p>
 * Test vectors from
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf
 */
public class AESCBCTest extends AESTest {
	private final byte[] iv = toBytes("000102030405060708090A0B0C0D0E0F");

	@Override
	BlockCipher getCipher(boolean forEncrypt, byte[] iv, byte[] key) {
		return BlockCipherFactory.createCipher(
				key.length == 16 ? "aes128-cbc" : "aes256-cbc",
				forEncrypt, key, iv);
	}

	@Test
	public void aes128Vector1() {
		checkVector(toBytes("2B7E151628AED2A6ABF7158809CF4F3C"),
				iv,
				csrcPlaintext,
				toBytes("7649ABAC8119B246CEE98E9B12E9197D" +
						"5086CB9B507219EE95DB113A917678B2" +
						"73BED6B8E3C1743B7116E69E22229516" +
						"3FF1CAA1681FAC09120ECA307586E1A7"));
	}

	@Test
	public void aes256Vector1() {
		checkVector(toBytes("603DEB1015CA71BE2B73AEF0857D7781" +
				"1F352C073B6108D72D9810A30914DFF4"),
				iv,
				csrcPlaintext,
				toBytes("F58C4C04D6E5F1BA779EABFB5F7BFBD6" +
						"9CFC4E967EDB808D679F777BC6702C7D" +
						"39F23369A9D9BACFA530E26304231461" +
						"B2EB05E2C39BE9FCDA6C19078C6A9D1B"));
	}
}

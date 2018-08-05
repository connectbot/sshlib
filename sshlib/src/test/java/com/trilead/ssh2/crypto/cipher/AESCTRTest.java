package com.trilead.ssh2.crypto.cipher;

import org.junit.Test;

/**
 * Testing composed AES-CTR mode.
 * <p>
 * Test vectors from
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf
 */
public class AESCTRTest extends AESTest {
	private final byte[] iv = toBytes("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");

	@Override
	BlockCipher getCipher(boolean forEncrypt, byte[] iv, byte[] key) {
		return BlockCipherFactory.createCipher(
				key.length == 16 ? "aes128-ctr" : "aes256-ctr",
				forEncrypt, key, iv);
	}

	@Test
	public void aes128Vector1() {
		checkVector(toBytes("2B7E151628AED2A6ABF7158809CF4F3C"),
				iv,
				csrcPlaintext,
				toBytes("874D6191B620E3261BEF6864990DB6CE"+
						"9806F66B7970FDFF8617187BB9FFFDFF"+
						"5AE4DF3EDBD5D35E5B4F09020DB03EAB"+
						"1E031DDA2FBE03D1792170A0F3009CEE"));
	}

	@Test
	public void aes256Vector1() {
		checkVector(toBytes("603DEB1015CA71BE2B73AEF0857D7781"+
				"1F352C073B6108D72D9810A30914DFF4"),
				iv,
				csrcPlaintext,
				toBytes("601EC313775789A5B7A7F504BBF3D228"+
						"F443E3CA4D62B59ACA84E990CACAF5C5"+
						"2B0930DAA23DE94CE87017BA2D84988D"+
						"DFC9C58DB67AADA613C2DD08457941A6"));
	}
}

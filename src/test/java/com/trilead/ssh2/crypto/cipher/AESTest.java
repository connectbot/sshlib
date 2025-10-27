package com.trilead.ssh2.crypto.cipher;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public abstract class AESTest {

	// Vectors from:
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf
	static final byte[] csrcPlaintext = toBytes(
			"6BC1BEE22E409F96E93D7E117393172A" +
					"AE2D8A571E03AC9C9EB76FAC45AF8E51" +
					"30C81C46A35CE411E5FBC1191A0A52EF" +
					"F69F2445DF4F9B17AD2B417BE66C3710");

	abstract BlockCipher getCipher(boolean forEncrypt, byte[] iv, byte[] key);

	@Test
	public void init_zeroKeySize_Failure() {
		assertThrows(IllegalArgumentException.class, () -> {
			BlockCipher aes = getCipher(true, new byte[16], new byte[0]);
		});
	}

	@Test
	public void init_8BitKeySize_Failure() {
		assertThrows(IllegalArgumentException.class, () -> {
			BlockCipher aes = getCipher(true, new byte[16], new byte[1]);
		});
	}

	@Test
	public void init_128BitKeySize_Success() {
		getCipher(true, new byte[16], new byte[128 / 8]);
		getCipher(false, new byte[16], new byte[128 / 8]);
	}

	@Test
	public void init_192BitKeySize_Success() {
		getCipher(true, new byte[16], new byte[192 / 8]);
		getCipher(false, new byte[16], new byte[192 / 8]);
	}

	@Test
	public void init_256BitKeySize_Success() {
		getCipher(true, new byte[16], new byte[256 / 8]);
		getCipher(false, new byte[16], new byte[256 / 8]);
	}

	@Test
	public void getBlockSize() {
		BlockCipher aes = getCipher(true, new byte[16], new byte[16]);
		assertEquals(16, aes.getBlockSize());
	}

	void checkVector(byte[] key, byte[] iv, byte[] plain, byte[] cipher) {
		BlockCipher encrypt = getCipher(true, iv, key);
		byte[] actualCipher = new byte[plain.length];
		transformBlocks(encrypt, plain, actualCipher);
		assertArrayEquals(cipher, actualCipher);

		BlockCipher decrypt = getCipher(false, iv, key);
		byte[] actualPlain = new byte[cipher.length];
		transformBlocks(decrypt, cipher, actualPlain);
		assertArrayEquals(plain, actualPlain);
	}

	private static final void transformBlocks(BlockCipher aes, byte[] in, byte[] out) {
		for (int i = 0; i < in.length; i += aes.getBlockSize()) {
			aes.transformBlock(in, i, out, i);
		}
	}

	static final byte[] toBytes(String input) {
		try {
			return Hex.decodeHex(input);
		} catch (DecoderException e) {
			throw new AssertionError("Cannot decode test vector: " + input);
		}
	}
}
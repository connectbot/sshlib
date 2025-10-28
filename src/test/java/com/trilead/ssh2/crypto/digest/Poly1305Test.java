package com.trilead.ssh2.crypto.digest;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Test Poly1305 using RFC 8439 test vectors.
 */
public class Poly1305Test
{
	@Test
	public void testRFC8439TestVector()
	{
		// RFC 8439 Section 2.5.2 test vector
		byte[] key = new byte[] {
			(byte) 0x85, (byte) 0xd6, (byte) 0xbe, (byte) 0x78, (byte) 0x57, (byte) 0x55, (byte) 0x6d, (byte) 0x33,
			(byte) 0x7f, (byte) 0x44, (byte) 0x52, (byte) 0xfe, (byte) 0x42, (byte) 0xd5, (byte) 0x06, (byte) 0xa8,
			(byte) 0x01, (byte) 0x03, (byte) 0x80, (byte) 0x8a, (byte) 0xfb, (byte) 0x0d, (byte) 0xb2, (byte) 0xfd,
			(byte) 0x4a, (byte) 0xbf, (byte) 0xf6, (byte) 0xaf, (byte) 0x41, (byte) 0x49, (byte) 0xf5, (byte) 0x1b
		};

		String message = "Cryptographic Forum Research Group";
		byte[] data = message.getBytes();

		byte[] expectedTag = new byte[] {
			(byte) 0xa8, (byte) 0x06, (byte) 0x1d, (byte) 0xc1, (byte) 0x30, (byte) 0x51, (byte) 0x36, (byte) 0xc6,
			(byte) 0xc2, (byte) 0x2b, (byte) 0x8b, (byte) 0xaf, (byte) 0x0c, (byte) 0x01, (byte) 0x27, (byte) 0xa9
		};

		Poly1305 poly = new Poly1305();
		poly.init(key);
		poly.update(data, 0, data.length);
		byte[] tag = new byte[16];
		poly.finish(tag, 0);

		assertArrayEquals(expectedTag, tag, "Poly1305 tag should match RFC 8439 test vector");
	}
}

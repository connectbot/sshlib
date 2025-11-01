package com.trilead.ssh2.transport;

import com.trilead.ssh2.crypto.cipher.BlockCipherFactory;
import com.trilead.ssh2.crypto.cipher.ChaCha20Poly1305;
import com.trilead.ssh2.crypto.digest.HMAC;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TransportConnectionTest {

	@Test
	public void testGetPacketOverheadEstimateWithBlockCipherAndMac() {
		ByteArrayInputStream is = new ByteArrayInputStream(new byte[0]);
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		SecureRandom rnd = new SecureRandom();

		TransportConnection tc = new TransportConnection(is, os, rnd);

		byte[] aesKey = new byte[16];
		byte[] aesIV = new byte[16];
		byte[] macKey = new byte[20];

		tc.changeSendCipher(
			BlockCipherFactory.createCipher("aes128-cbc", true, aesKey, aesIV),
			new HMAC("hmac-sha1", macKey)
		);

		int overhead = tc.getPacketOverheadEstimate();

		assertTrue(overhead > 0, "Overhead should be positive");
		assertEquals(5 + 4 + (16 - 1) + 20, overhead,
			"Overhead should be: 5 (header) + 4 (extra) + 15 (max padding - 1) + 20 (MAC size)");
	}

	@Test
	public void testGetPacketOverheadEstimateWithAeadCipher() {
		ByteArrayInputStream is = new ByteArrayInputStream(new byte[0]);
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		SecureRandom rnd = new SecureRandom();

		TransportConnection tc = new TransportConnection(is, os, rnd);

		byte[] key = new byte[64];
		ChaCha20Poly1305 aeadCipher = new ChaCha20Poly1305();
		aeadCipher.init(true, key, null);

		tc.changeSendAeadCipher(aeadCipher);

		int overhead = tc.getPacketOverheadEstimate();

		assertTrue(overhead > 0, "Overhead should be positive");
		assertEquals(4 + 1 + (8 - 1) + 16, overhead,
			"Overhead should be: 4 (encrypted length) + 1 (padding_length byte) + 7 (max padding - 1) + 16 (tag size)");
	}

	@Test
	public void testGetPacketOverheadEstimateInitialState() {
		ByteArrayInputStream is = new ByteArrayInputStream(new byte[0]);
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		SecureRandom rnd = new SecureRandom();

		TransportConnection tc = new TransportConnection(is, os, rnd);

		int overhead = tc.getPacketOverheadEstimate();

		assertTrue(overhead > 0, "Overhead should be positive even in initial state");
	}
}

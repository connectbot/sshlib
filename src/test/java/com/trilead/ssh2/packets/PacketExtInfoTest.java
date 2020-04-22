package com.trilead.ssh2.packets;

import org.junit.Test;

import java.io.IOException;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class PacketExtInfoTest {
	@Test
	public void getPayload_NullPayload_IsEmpty() {
		PacketExtInfo p = new PacketExtInfo(Collections.emptyMap());
		assertNotNull(p.getPayload());
		assertEquals(Collections.emptyMap(), p.getExtNameToValue());
	}

	@Test(expected = IOException.class)
	public void packetWithPadding_Fails() throws IOException {
		byte[] unpaddedPacket = new PacketExtInfo(Collections.emptyMap()).getPayload();
		byte[] paddedPacket = new byte[unpaddedPacket.length + 1];
		System.arraycopy(unpaddedPacket, 0, paddedPacket, 0, unpaddedPacket.length);
		new PacketExtInfo(paddedPacket, 0, paddedPacket.length);
	}

	@Test(expected = IOException.class)
	public void wrongPacket_Fails() throws IOException {
		byte[] wrongPacket = new PacketGlobalTrileadPing().getPayload();
		new PacketExtInfo(wrongPacket, 0, wrongPacket.length);
	}

	@Test
	public void createPacketAndParsePayload_Success() throws IOException {
		byte[] payload = new PacketExtInfo(Collections.singletonMap("test", "value")).getPayload();
		PacketExtInfo copy = new PacketExtInfo(payload, 0, payload.length);
		assertEquals("value", copy.getExtNameToValue().get("test"));
	}
}

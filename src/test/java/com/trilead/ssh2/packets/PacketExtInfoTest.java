package com.trilead.ssh2.packets;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class PacketExtInfoTest {
	@Test
	public void getPayload_NullPayload_IsEmpty() {
		PacketExtInfo p = new PacketExtInfo(Collections.emptyMap());
		assertNotNull(p.getPayload());
		assertEquals(Collections.emptyMap(), p.getExtNameToValue());
	}

	@Test
	public void packetWithPadding_Fails() {
		assertThrows(IOException.class, () -> {
		byte[] unpaddedPacket = new PacketExtInfo(Collections.emptyMap()).getPayload();
		byte[] paddedPacket = new byte[unpaddedPacket.length + 1];
		System.arraycopy(unpaddedPacket, 0, paddedPacket, 0, unpaddedPacket.length);
		new PacketExtInfo(paddedPacket, 0, paddedPacket.length);
		});
	}

	@Test
	public void wrongPacket_Fails() {
		assertThrows(IOException.class, () -> {
		byte[] wrongPacket = new PacketGlobalTrileadPing().getPayload();
		new PacketExtInfo(wrongPacket, 0, wrongPacket.length);
		});
	}

	@Test
	public void createPacketAndParsePayload_Success() throws IOException {
		byte[] payload = new PacketExtInfo(Collections.singletonMap("test", "value")).getPayload();
		PacketExtInfo copy = new PacketExtInfo(payload, 0, payload.length);
		assertEquals(copy.getExtNameToValue().get("test"), "value");
	}
}

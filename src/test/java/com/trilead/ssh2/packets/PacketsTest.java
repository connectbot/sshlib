package com.trilead.ssh2.packets;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PacketsTest {
	@Test
	public void getMessageName_BeyondEnd_Fails() {
		assertEquals(Packets.getMessageName(8928392), "UNKNOWN MSG 8928392");
	}

	@Test
	public void getMessageName_Negative_Fails() {
		assertEquals(Packets.getMessageName(-1), "UNKNOWN MSG -1");
	}
}

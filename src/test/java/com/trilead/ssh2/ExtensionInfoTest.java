package com.trilead.ssh2;

import com.trilead.ssh2.packets.PacketExtInfo;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ExtensionInfoTest {
	@Test
	public void fromPacketExtInfo_NoArgs_NoAlgs() {
		PacketExtInfo packet = new PacketExtInfo(Collections.emptyMap());
		ExtensionInfo extInfo = ExtensionInfo.fromPacketExtInfo(packet);
		assertTrue(extInfo.getSignatureAlgorithmsAccepted().isEmpty());
	}

	@Test
	public void noExtInfoSeen_HasNoSigAlgs() {
		ExtensionInfo noExtInfo = ExtensionInfo.noExtInfoSeen();
		assertTrue(noExtInfo.getSignatureAlgorithmsAccepted().isEmpty());
	}

	@Test
	public void parsesSigAlgs() {
		PacketExtInfo packet = new PacketExtInfo(Collections.singletonMap("server-sig-algs", "rsa-sha2-256,rsa-sha2-512"));
		ExtensionInfo extInfo = ExtensionInfo.fromPacketExtInfo(packet);

		Set<String> sigAlgs = extInfo.getSignatureAlgorithmsAccepted();
		assertEquals(2, sigAlgs.size());
		assertTrue(sigAlgs.contains("rsa-sha2-256"));
		assertTrue(sigAlgs.contains("rsa-sha2-512"));
	}
}

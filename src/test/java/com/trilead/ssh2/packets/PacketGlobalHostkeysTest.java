package com.trilead.ssh2.packets;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PacketGlobalHostkeysTest {

	@Test
	public void parseVendorName_Success() throws Exception {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_GLOBAL_REQUEST);
		tw.writeString("hostkeys-00@openssh.com");
		tw.writeBoolean(false);
		tw.writeString(new byte[] { 0x01, 0x02, 0x03 }, 0, 3);
		tw.writeString(new byte[] { 0x04, 0x05 }, 0, 2);

		byte[] data = tw.getBytes();
		PacketGlobalHostkeys packet = new PacketGlobalHostkeys(data, 0, data.length);

		assertThat(packet.getRequestName(), equalTo("hostkeys-00@openssh.com"));
		assertThat(packet.getHostkeys(), hasSize(2));
		assertThat(packet.getHostkeys().get(0), equalTo(new byte[] { 0x01, 0x02, 0x03 }));
		assertThat(packet.getHostkeys().get(1), equalTo(new byte[] { 0x04, 0x05 }));
	}

	@Test
	public void parseStandardName_Success() throws Exception {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_GLOBAL_REQUEST);
		tw.writeString("hostkeys");
		tw.writeBoolean(false);
		tw.writeString(new byte[] { 0x01, 0x02, 0x03 }, 0, 3);

		byte[] data = tw.getBytes();
		PacketGlobalHostkeys packet = new PacketGlobalHostkeys(data, 0, data.length);

		assertThat(packet.getRequestName(), equalTo("hostkeys"));
		assertThat(packet.getHostkeys(), hasSize(1));
	}

	@Test
	public void parseEmpty_Success() throws Exception {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_GLOBAL_REQUEST);
		tw.writeString("hostkeys-00@openssh.com");
		tw.writeBoolean(false);

		byte[] data = tw.getBytes();
		PacketGlobalHostkeys packet = new PacketGlobalHostkeys(data, 0, data.length);

		assertThat(packet.getHostkeys(), hasSize(0));
	}

	@Test
	public void parseWrongMessageType_Failure() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_REQUEST_SUCCESS);
		tw.writeString("hostkeys-00@openssh.com");

		byte[] data = tw.getBytes();
		assertThrows(IOException.class, () -> {
			new PacketGlobalHostkeys(data, 0, data.length);
		});
	}

	@Test
	public void parseWithOffset_Success() throws Exception {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0xFF);
		tw.writeByte(0xFF);
		tw.writeByte(Packets.SSH_MSG_GLOBAL_REQUEST);
		tw.writeString("hostkeys-00@openssh.com");
		tw.writeBoolean(false);
		tw.writeString(new byte[] { 0x01, 0x02 }, 0, 2);

		byte[] data = tw.getBytes();
		PacketGlobalHostkeys packet = new PacketGlobalHostkeys(data, 2, data.length - 2);

		assertThat(packet.getHostkeys(), hasSize(1));
		assertThat(packet.getHostkeys().get(0), equalTo(new byte[] { 0x01, 0x02 }));
	}

	@Test
	public void parseMultipleKeys_Success() throws Exception {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_GLOBAL_REQUEST);
		tw.writeString("hostkeys-00@openssh.com");
		tw.writeBoolean(false);

		for (int i = 0; i < 5; i++) {
			byte[] key = new byte[i + 1];
			Arrays.fill(key, (byte) i);
			tw.writeString(key, 0, key.length);
		}

		byte[] data = tw.getBytes();
		PacketGlobalHostkeys packet = new PacketGlobalHostkeys(data, 0, data.length);

		assertThat(packet.getHostkeys(), hasSize(5));
		for (int i = 0; i < 5; i++) {
			byte[] expected = new byte[i + 1];
			Arrays.fill(expected, (byte) i);
			assertThat(packet.getHostkeys().get(i), equalTo(expected));
		}
	}
}

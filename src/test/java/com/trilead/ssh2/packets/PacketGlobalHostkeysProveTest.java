package com.trilead.ssh2.packets;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PacketGlobalHostkeysProveTest {

	@Test
	public void createRequest_Success() throws Exception {
		byte[] key1 = new byte[] { 0x01, 0x02, 0x03 };
		byte[] key2 = new byte[] { 0x04, 0x05 };

		PacketGlobalHostkeysProve packet = new PacketGlobalHostkeysProve(
			PacketGlobalHostkeysProve.HOSTKEYS_PROVE_VENDOR,
			Arrays.asList(key1, key2)
		);

		byte[] payload = packet.getPayload();
		TypesReader tr = new TypesReader(payload);

		assertThat(tr.readByte(), equalTo(Packets.SSH_MSG_GLOBAL_REQUEST));
		assertThat(tr.readString(), equalTo(PacketGlobalHostkeysProve.HOSTKEYS_PROVE_VENDOR));
		assertThat(tr.readBoolean(), equalTo(true));
		assertThat(tr.readByteString(), equalTo(key1));
		assertThat(tr.readByteString(), equalTo(key2));
		assertThat(tr.remain(), equalTo(0));
	}

	@Test
	public void createRequestStandard_Success() throws Exception {
		byte[] key1 = new byte[] { 0x01, 0x02 };

		PacketGlobalHostkeysProve packet = new PacketGlobalHostkeysProve(
			PacketGlobalHostkeysProve.HOSTKEYS_PROVE_STANDARD,
			Arrays.asList(key1)
		);

		byte[] payload = packet.getPayload();
		TypesReader tr = new TypesReader(payload);

		assertThat(tr.readByte(), equalTo(Packets.SSH_MSG_GLOBAL_REQUEST));
		assertThat(tr.readString(), equalTo(PacketGlobalHostkeysProve.HOSTKEYS_PROVE_STANDARD));
		assertThat(tr.readBoolean(), equalTo(true));
	}

	@Test
	public void parseResponse_Success() throws Exception {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_REQUEST_SUCCESS);
		tw.writeString(new byte[] { 0x01, 0x02, 0x03 }, 0, 3);
		tw.writeString(new byte[] { 0x04, 0x05 }, 0, 2);

		byte[] data = tw.getBytes();
		PacketGlobalHostkeysProve packet = new PacketGlobalHostkeysProve(data, 0, data.length, true);

		assertThat(packet.getSignatures(), hasSize(2));
		assertThat(packet.getSignatures().get(0), equalTo(new byte[] { 0x01, 0x02, 0x03 }));
		assertThat(packet.getSignatures().get(1), equalTo(new byte[] { 0x04, 0x05 }));
	}

	@Test
	public void parseRequest_Success() throws Exception {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_GLOBAL_REQUEST);
		tw.writeString(PacketGlobalHostkeysProve.HOSTKEYS_PROVE_VENDOR);
		tw.writeBoolean(true);
		tw.writeString(new byte[] { 0x01, 0x02 }, 0, 2);

		byte[] data = tw.getBytes();
		PacketGlobalHostkeysProve packet = new PacketGlobalHostkeysProve(data, 0, data.length, false);

		assertThat(packet.getRequestName(), equalTo(PacketGlobalHostkeysProve.HOSTKEYS_PROVE_VENDOR));
		assertThat(packet.getHostkeys(), hasSize(1));
		assertThat(packet.getHostkeys().get(0), equalTo(new byte[] { 0x01, 0x02 }));
	}

	@Test
	public void parseResponseWrongType_Failure() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_REQUEST_FAILURE);

		byte[] data = tw.getBytes();
		assertThrows(IOException.class, () -> {
			new PacketGlobalHostkeysProve(data, 0, data.length, true);
		});
	}

	@Test
	public void parseRequestWrongType_Failure() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_REQUEST_SUCCESS);

		byte[] data = tw.getBytes();
		assertThrows(IOException.class, () -> {
			new PacketGlobalHostkeysProve(data, 0, data.length, false);
		});
	}

	@Test
	public void getPayloadFromResponse_Failure() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_REQUEST_SUCCESS);
		tw.writeString(new byte[] { 0x01 }, 0, 1);

		byte[] data = tw.getBytes();
		PacketGlobalHostkeysProve packet;
		try {
			packet = new PacketGlobalHostkeysProve(data, 0, data.length, true);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		PacketGlobalHostkeysProve finalPacket = packet;
		assertThrows(IllegalStateException.class, () -> {
			finalPacket.getPayload();
		});
	}

	@Test
	public void parseMultipleSignatures_Success() throws Exception {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_REQUEST_SUCCESS);

		for (int i = 0; i < 5; i++) {
			byte[] sig = new byte[i + 1];
			Arrays.fill(sig, (byte) i);
			tw.writeString(sig, 0, sig.length);
		}

		byte[] data = tw.getBytes();
		PacketGlobalHostkeysProve packet = new PacketGlobalHostkeysProve(data, 0, data.length, true);

		assertThat(packet.getSignatures(), hasSize(5));
		for (int i = 0; i < 5; i++) {
			byte[] expected = new byte[i + 1];
			Arrays.fill(expected, (byte) i);
			assertThat(packet.getSignatures().get(i), equalTo(expected));
		}
	}
}

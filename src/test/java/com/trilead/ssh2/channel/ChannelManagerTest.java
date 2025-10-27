package com.trilead.ssh2.channel;

import com.trilead.ssh2.ChannelCondition;
import com.trilead.ssh2.packets.Packets;
import com.trilead.ssh2.transport.ITransportConnection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Test coverage for ChannelManager.
 *
 * Note: ChannelManager is a complex class that's tightly coupled with the transport layer
 * and the SSH protocol. These tests focus on unit-testable functionality using mocks.
 * Integration tests for full channel operations are covered by OpenSSHCompatibilityTest.
 */
@ExtendWith(MockitoExtension.class)
public class ChannelManagerTest {

	@Mock
	private ITransportConnection mockTransportConnection;

	private ChannelManager channelManager;

	@BeforeEach
	public void setUp() {
		channelManager = new ChannelManager(mockTransportConnection);
	}

	@Test
	public void testConstructor() {
		assertNotNull(channelManager);
		// Verify that the ChannelManager registered itself as a message handler
		verify(mockTransportConnection).registerMessageHandler(channelManager, 80, 100);
	}

	@Test
	public void testRegisterX11Cookie() {
		String cookie = "1234567890abcdef";
		X11ServerData data = new X11ServerData();
		data.hostname = "localhost";
		data.port = 6000;

		channelManager.registerX11Cookie(cookie, data);

		// Verify the cookie was registered by trying to check it
		X11ServerData retrieved = channelManager.checkX11Cookie(cookie);
		assertNotNull(retrieved);
		assertEquals("localhost", retrieved.hostname);
		assertEquals(6000, retrieved.port);
	}

	@Test
	public void testCheckX11CookieNotRegistered() {
		X11ServerData result = channelManager.checkX11Cookie("nonexistent");
		assertNull(result);
	}

	@Test
	public void testCheckX11CookieWithNull() {
		X11ServerData result = channelManager.checkX11Cookie(null);
		assertNull(result);
	}

	@Test
	public void testUnRegisterX11CookieWithoutKill() {
		String cookie = "abcdef1234567890";
		X11ServerData data = new X11ServerData();
		data.hostname = "testhost";
		data.port = 6001;

		channelManager.registerX11Cookie(cookie, data);
		assertNotNull(channelManager.checkX11Cookie(cookie));

		channelManager.unRegisterX11Cookie(cookie, false);

		// Cookie should be removed
		assertNull(channelManager.checkX11Cookie(cookie));
	}

	@Test
	public void testUnRegisterX11CookieWithNull() {
		assertThrows(IllegalStateException.class, () -> {
		channelManager.unRegisterX11Cookie(null, false);
		});
	}

	@Test
	public void testMsgChannelDataTooShort() throws IOException {
		byte[] msg = new byte[8]; // Too short, needs at least 9 bytes
		msg[0] = Packets.SSH_MSG_CHANNEL_DATA;

		try {
			channelManager.msgChannelData(msg, 8);
			fail("Should throw IOException for message too short");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("wrong size"));
		}
	}

	@Test
	public void testMsgChannelDataNonExistentChannel() throws IOException {
		// Create a valid SSH_MSG_CHANNEL_DATA message for a non-existent channel
		byte[] msg = new byte[13];
		msg[0] = Packets.SSH_MSG_CHANNEL_DATA;
		// Channel ID = 999 (doesn't exist)
		msg[1] = 0;
		msg[2] = 0;
		msg[3] = 3;
		msg[4] = (byte) 231; // 999 in bytes
		// Data length = 4
		msg[5] = 0;
		msg[6] = 0;
		msg[7] = 0;
		msg[8] = 4;
		// 4 bytes of data
		msg[9] = 0;
		msg[10] = 0;
		msg[11] = 0;
		msg[12] = 0;

		try {
			channelManager.msgChannelData(msg, 13);
			fail("Should throw IOException for non-existent channel");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("non-existent channel"));
		}
	}

	@Test
	public void testMsgChannelExtendedDataTooShort() throws IOException {
		byte[] msg = new byte[12]; // Too short, needs at least 13 bytes
		msg[0] = Packets.SSH_MSG_CHANNEL_EXTENDED_DATA;

		try {
			channelManager.msgChannelExtendedData(msg, 12);
			fail("Should throw IOException for message too short");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("wrong size"));
		}
	}

	@Test
	public void testMsgChannelExtendedDataNonExistentChannel() throws IOException {
		// Create a valid SSH_MSG_CHANNEL_EXTENDED_DATA message for a non-existent channel
		byte[] msg = new byte[17];
		msg[0] = Packets.SSH_MSG_CHANNEL_EXTENDED_DATA;
		// Channel ID = 999
		msg[1] = 0;
		msg[2] = 0;
		msg[3] = 3;
		msg[4] = (byte) 231;
		// Data type = SSH_EXTENDED_DATA_STDERR (1)
		msg[5] = 0;
		msg[6] = 0;
		msg[7] = 0;
		msg[8] = 1;
		// Data length = 4
		msg[9] = 0;
		msg[10] = 0;
		msg[11] = 0;
		msg[12] = 4;
		// 4 bytes of data
		msg[13] = 0;
		msg[14] = 0;
		msg[15] = 0;
		msg[16] = 0;

		try {
			channelManager.msgChannelExtendedData(msg, 17);
			fail("Should throw IOException for non-existent channel");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("non-existent channel"));
		}
	}

	@Test
	public void testMsgChannelWindowAdjustWrongSize() throws IOException {
		byte[] msg = new byte[8]; // Wrong size, needs exactly 9 bytes
		msg[0] = Packets.SSH_MSG_CHANNEL_WINDOW_ADJUST;

		try {
			channelManager.msgChannelWindowAdjust(msg, 8);
			fail("Should throw IOException for wrong message size");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("wrong size"));
		}
	}

	@Test
	public void testMsgChannelWindowAdjustNonExistentChannel() throws IOException {
		byte[] msg = new byte[9];
		msg[0] = Packets.SSH_MSG_CHANNEL_WINDOW_ADJUST;
		// Channel ID = 999
		msg[1] = 0;
		msg[2] = 0;
		msg[3] = 3;
		msg[4] = (byte) 231;
		// Window adjustment = 1000
		msg[5] = 0;
		msg[6] = 0;
		msg[7] = 3;
		msg[8] = (byte) 232;

		try {
			channelManager.msgChannelWindowAdjust(msg, 9);
			fail("Should throw IOException for non-existent channel");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("non-existent channel"));
		}
	}

	@Test
	public void testMsgChannelEOFWrongSize() throws IOException {
		byte[] msg = new byte[4]; // Wrong size, needs exactly 5 bytes
		msg[0] = Packets.SSH_MSG_CHANNEL_EOF;

		try {
			channelManager.msgChannelEOF(msg, 4);
			fail("Should throw IOException for wrong message size");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("wrong size"));
		}
	}

	@Test
	public void testMsgChannelEOFNonExistentChannel() throws IOException {
		byte[] msg = new byte[5];
		msg[0] = Packets.SSH_MSG_CHANNEL_EOF;
		// Channel ID = 999
		msg[1] = 0;
		msg[2] = 0;
		msg[3] = 3;
		msg[4] = (byte) 231;

		try {
			channelManager.msgChannelEOF(msg, 5);
			fail("Should throw IOException for non-existent channel");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("non-existent channel"));
		}
	}

	@Test
	public void testMsgChannelCloseWrongSize() throws IOException {
		byte[] msg = new byte[4]; // Wrong size, needs exactly 5 bytes
		msg[0] = Packets.SSH_MSG_CHANNEL_CLOSE;

		try {
			channelManager.msgChannelClose(msg, 4);
			fail("Should throw IOException for wrong message size");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("wrong size"));
		}
	}

	@Test
	public void testMsgChannelCloseNonExistentChannel() throws IOException {
		byte[] msg = new byte[5];
		msg[0] = Packets.SSH_MSG_CHANNEL_CLOSE;
		// Channel ID = 999
		msg[1] = 0;
		msg[2] = 0;
		msg[3] = 3;
		msg[4] = (byte) 231;

		try {
			channelManager.msgChannelClose(msg, 5);
			fail("Should throw IOException for non-existent channel");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("non-existent channel"));
		}
	}

	@Test
	public void testMsgChannelSuccessWrongSize() throws IOException {
		byte[] msg = new byte[4]; // Wrong size, needs exactly 5 bytes
		msg[0] = Packets.SSH_MSG_CHANNEL_SUCCESS;

		try {
			channelManager.msgChannelSuccess(msg, 4);
			fail("Should throw IOException for wrong message size");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("wrong size"));
		}
	}

	@Test
	public void testMsgChannelSuccessNonExistentChannel() throws IOException {
		byte[] msg = new byte[5];
		msg[0] = Packets.SSH_MSG_CHANNEL_SUCCESS;
		// Channel ID = 999
		msg[1] = 0;
		msg[2] = 0;
		msg[3] = 3;
		msg[4] = (byte) 231;

		try {
			channelManager.msgChannelSuccess(msg, 5);
			fail("Should throw IOException for non-existent channel");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("non-existent channel"));
		}
	}

	@Test
	public void testMsgChannelFailureWrongSize() throws IOException {
		byte[] msg = new byte[4]; // Wrong size, needs exactly 5 bytes
		msg[0] = Packets.SSH_MSG_CHANNEL_FAILURE;

		try {
			channelManager.msgChannelFailure(msg, 4);
			fail("Should throw IOException for wrong message size");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("wrong size"));
		}
	}

	@Test
	public void testMsgChannelFailureNonExistentChannel() throws IOException {
		byte[] msg = new byte[5];
		msg[0] = Packets.SSH_MSG_CHANNEL_FAILURE;
		// Channel ID = 999
		msg[1] = 0;
		msg[2] = 0;
		msg[3] = 3;
		msg[4] = (byte) 231;

		try {
			channelManager.msgChannelFailure(msg, 5);
			fail("Should throw IOException for non-existent channel");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("non-existent channel"));
		}
	}

	@Test
	public void testMsgChannelOpenFailureTooShort() throws IOException {
		byte[] msg = new byte[4]; // Too short, needs at least 5 bytes
		msg[0] = Packets.SSH_MSG_CHANNEL_OPEN_FAILURE;

		try {
			channelManager.msgChannelOpenFailure(msg, 4);
			fail("Should throw IOException for message too short");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("wrong size"));
		}
	}

	@Test
	public void testMsgGlobalRequestWithoutReply() throws IOException {
		// Create a global request message without wanting a reply
		byte[] msg = new byte[20];
		msg[0] = Packets.SSH_MSG_GLOBAL_REQUEST;
		// Request name "test" (4 bytes length + 4 bytes string)
		msg[1] = 0;
		msg[2] = 0;
		msg[3] = 0;
		msg[4] = 4;
		msg[5] = 't';
		msg[6] = 'e';
		msg[7] = 's';
		msg[8] = 't';
		// Want reply = false
		msg[9] = 0;

		// Should not throw, just ignore
		channelManager.msgGlobalRequest(msg, 10);

		// No message should be sent since wantReply is false
		verify(mockTransportConnection, never()).sendAsynchronousMessage(any(byte[].class));
	}

	@Test
	public void testMsgGlobalRequestWithReply() throws IOException {
		// Create a global request message wanting a reply
		byte[] msg = new byte[20];
		msg[0] = Packets.SSH_MSG_GLOBAL_REQUEST;
		// Request name "test" (4 bytes length + 4 bytes string)
		msg[1] = 0;
		msg[2] = 0;
		msg[3] = 0;
		msg[4] = 4;
		msg[5] = 't';
		msg[6] = 'e';
		msg[7] = 's';
		msg[8] = 't';
		// Want reply = true
		msg[9] = 1;

		channelManager.msgGlobalRequest(msg, 10);

		// Should send a failure response
		verify(mockTransportConnection, times(1)).sendAsynchronousMessage(any(byte[].class));
	}

	@Test
	public void testMsgGlobalSuccess() {
		channelManager.msgGlobalSuccess();
		// Just verify it doesn't throw
		// The internal state change can't be easily tested without reflection
	}

	@Test
	public void testMsgGlobalFailure() {
		channelManager.msgGlobalFailure();
		// Just verify it doesn't throw
		// The internal state change can't be easily tested without reflection
	}

	@Test
	public void testHandleMessageWithNullShutdown() throws IOException {
		channelManager.handleMessage(null, 0);
		// Should not throw, handles shutdown gracefully
	}

	@Test
	public void testHandleMessageWithUnknownType() {
		byte[] msg = new byte[1];
		msg[0] = (byte) 255; // Unknown message type

		try {
			channelManager.handleMessage(msg, 1);
			fail("Should throw IOException for unknown message type");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("Cannot handle unknown channel message"));
		}
	}

	@Test
	public void testHandleMessageChannelOpenConfirmation() throws IOException {
		// This will fail because there's no channel, but it tests the routing
		byte[] msg = new byte[17];
		msg[0] = Packets.SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
		// Fill with dummy data
		for (int i = 1; i < 17; i++) {
			msg[i] = 0;
		}

		try {
			channelManager.handleMessage(msg, 17);
			fail("Should throw IOException for non-existent channel");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("non-existent channel"));
		}
	}

	@Test
	public void testHandleMessageRoutingChannelData() throws IOException {
		// Test SSH_MSG_CHANNEL_DATA routing - message too short
		byte[] dataMsg = new byte[9];
		dataMsg[0] = Packets.SSH_MSG_CHANNEL_DATA;
		try {
			channelManager.handleMessage(dataMsg, 9);
			fail("Should throw IOException");
		} catch (IOException e) {
			assertTrue(e.getMessage().toLowerCase().contains("wrong size"),
					"Expected size error but got: " + e.getMessage());
		}
	}

	@Test
	public void testHandleMessageRoutingChannelEOF() throws IOException {
		// Test SSH_MSG_CHANNEL_EOF routing - should fail on non-existent channel
		byte[] eofMsg = new byte[5];
		eofMsg[0] = Packets.SSH_MSG_CHANNEL_EOF;
		// Set channel ID to 0
		eofMsg[1] = 0;
		eofMsg[2] = 0;
		eofMsg[3] = 0;
		eofMsg[4] = 0;
		try {
			channelManager.handleMessage(eofMsg, 5);
			fail("Should throw IOException");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("Unexpected"),
					"Expected 'Unexpected' in message but got: " + e.getMessage());
		}
	}

	@Test
	public void testHandleMessageRoutingChannelClose() throws IOException {
		// Test SSH_MSG_CHANNEL_CLOSE routing - should fail on non-existent channel
		byte[] closeMsg = new byte[5];
		closeMsg[0] = Packets.SSH_MSG_CHANNEL_CLOSE;
		// Set channel ID to 0
		closeMsg[1] = 0;
		closeMsg[2] = 0;
		closeMsg[3] = 0;
		closeMsg[4] = 0;
		try {
			channelManager.handleMessage(closeMsg, 5);
			fail("Should throw IOException");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("Unexpected"),
					"Expected 'Unexpected' in message but got: " + e.getMessage());
		}
	}

	@Test
	public void testCloseAllChannels() {
		// Should not throw even with no channels
		channelManager.closeAllChannels();
	}

	// Note: testRequestGlobalForward removed because it blocks on waitForGlobalRequestResult
	// which requires complex mock setup with threading. This is better tested via integration tests.

	@Test
	public void testRegisterThreadWhenNotAllowed() throws IOException {
		// First, simulate shutdown by calling handleMessage with null
		channelManager.handleMessage(null, 0);

		// Now try to register a thread - should fail
		IChannelWorkerThread mockThread = mock(IChannelWorkerThread.class);

		try {
			channelManager.registerThread(mockThread);
			fail("Should throw IOException when connection is closed");
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("Too late") || e.getMessage().contains("closed"));
		}
	}

	@Test
	public void testMultipleX11Cookies() {
		String cookie1 = "cookie1";
		String cookie2 = "cookie2";

		X11ServerData data1 = new X11ServerData();
		data1.hostname = "host1";
		data1.port = 6000;

		X11ServerData data2 = new X11ServerData();
		data2.hostname = "host2";
		data2.port = 6001;

		channelManager.registerX11Cookie(cookie1, data1);
		channelManager.registerX11Cookie(cookie2, data2);

		X11ServerData retrieved1 = channelManager.checkX11Cookie(cookie1);
		X11ServerData retrieved2 = channelManager.checkX11Cookie(cookie2);

		assertNotNull(retrieved1);
		assertNotNull(retrieved2);
		assertEquals("host1", retrieved1.hostname);
		assertEquals(6000, retrieved1.port);
		assertEquals("host2", retrieved2.hostname);
		assertEquals(6001, retrieved2.port);

		channelManager.unRegisterX11Cookie(cookie1, false);

		assertNull(channelManager.checkX11Cookie(cookie1));
		assertNotNull(channelManager.checkX11Cookie(cookie2));
	}

	@Test
	public void testCloseChannelForced() throws IOException {
		Channel channel = new Channel(channelManager);
		channel.localID = 100;
		channel.remoteID = 200;
		channel.state = Channel.STATE_OPEN;

		channelManager.closeChannel(channel, "Test close", true);
		verify(mockTransportConnection).sendMessage(any(byte[].class));
		assertEquals(Channel.STATE_CLOSED, channel.state);
	}

	@Test
	public void testSendEOF() throws IOException {
		Channel channel = new Channel(channelManager);
		channel.localID = 100;
		channel.remoteID = 200;
		channel.state = Channel.STATE_OPEN;

		channelManager.sendEOF(channel);
		verify(mockTransportConnection).sendMessage(any(byte[].class));
	}

	@Test
	public void testSendEOFOnClosedChannel() throws IOException {
		Channel channel = new Channel(channelManager);
		channel.localID = 100;
		channel.remoteID = 200;
		channel.state = Channel.STATE_CLOSED;

		channelManager.sendEOF(channel);
		verify(mockTransportConnection, never()).sendMessage(any(byte[].class));
	}

	@Test
	public void testSendData() throws IOException {
		Channel channel = new Channel(channelManager);
		channel.localID = 100;
		channel.remoteID = 200;
		channel.state = Channel.STATE_OPEN;
		channel.remoteWindow = 32768;

		byte[] data = "Hello World".getBytes();
		channelManager.sendData(channel, data, 0, data.length);
		verify(mockTransportConnection, atLeastOnce()).sendMessage(any(byte[].class));
	}

	@Test
	public void testGetAvailable() {
		Channel channel = new Channel(channelManager);
		channel.localID = 100;

		int available = channelManager.getAvailable(channel, false);
		assertEquals(0, available);
	}

	@Test
	public void testWaitForConditionTimeout() {
		Channel channel = new Channel(channelManager);
		channel.localID = 100;
		channel.state = Channel.STATE_OPEN;

		int result = channelManager.waitForCondition(channel, 100, ChannelCondition.EOF);
		assertTrue((result & ChannelCondition.TIMEOUT) != 0);
	}

	@Test
	public void testWaitForConditionClosed() {
		Channel channel = new Channel(channelManager);
		channel.localID = 100;
		channel.state = Channel.STATE_CLOSED;

		int result = channelManager.waitForCondition(channel, 1000, ChannelCondition.EOF);
		assertTrue((result & ChannelCondition.CLOSED) != 0);
	}

	@Test
	public void testMsgChannelOpenWithForwardedTcpip() throws IOException {
		byte[] msg = new byte[100];
		msg[0] = Packets.SSH_MSG_CHANNEL_OPEN;

		String channelType = "forwarded-tcpip";
		int offset = 1;
		msg[offset++] = (byte) (channelType.length() >>> 24);
		msg[offset++] = (byte) (channelType.length() >>> 16);
		msg[offset++] = (byte) (channelType.length() >>> 8);
		msg[offset++] = (byte) (channelType.length());
		System.arraycopy(channelType.getBytes(), 0, msg, offset, channelType.length());

		try {
			channelManager.msgChannelOpen(msg, msg.length);
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("forwarding") ||
				e.getMessage().contains("registered") ||
				e.getMessage().contains("open"));
		}
	}

	@Test
	public void testMsgChannelOpenWithAuthAgent() throws IOException {
		byte[] msg = new byte[100];
		msg[0] = Packets.SSH_MSG_CHANNEL_OPEN;

		String channelType = "auth-agent@openssh.com";
		int offset = 1;
		msg[offset++] = (byte) (channelType.length() >>> 24);
		msg[offset++] = (byte) (channelType.length() >>> 16);
		msg[offset++] = (byte) (channelType.length() >>> 8);
		msg[offset++] = (byte) (channelType.length());
		System.arraycopy(channelType.getBytes(), 0, msg, offset, channelType.length());

		try {
			channelManager.msgChannelOpen(msg, msg.length);
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("agent") ||
				e.getMessage().contains("enabled") ||
				e.getMessage().contains("open"));
		}
	}

	@Test
	public void testMsgChannelOpenWithX11() throws IOException {
		byte[] msg = new byte[100];
		msg[0] = Packets.SSH_MSG_CHANNEL_OPEN;

		String channelType = "x11";
		int offset = 1;
		msg[offset++] = (byte) (channelType.length() >>> 24);
		msg[offset++] = (byte) (channelType.length() >>> 16);
		msg[offset++] = (byte) (channelType.length() >>> 8);
		msg[offset++] = (byte) (channelType.length());
		System.arraycopy(channelType.getBytes(), 0, msg, offset, channelType.length());

		try {
			channelManager.msgChannelOpen(msg, msg.length);
		} catch (IOException e) {
			assertTrue(e.getMessage().contains("x11") ||
				e.getMessage().contains("cookie") ||
				e.getMessage().contains("open"));
		}
	}

	@Test
	public void testMsgChannelOpenWithUnknownType() throws IOException {
		byte[] msg = new byte[100];
		msg[0] = Packets.SSH_MSG_CHANNEL_OPEN;

		String channelType = "unknown-channel-type";
		int offset = 1;
		msg[offset++] = (byte) (channelType.length() >>> 24);
		msg[offset++] = (byte) (channelType.length() >>> 16);
		msg[offset++] = (byte) (channelType.length() >>> 8);
		msg[offset++] = (byte) (channelType.length());
		System.arraycopy(channelType.getBytes(), 0, msg, offset, channelType.length());
		offset += channelType.length();

		msg[offset++] = 0;
		msg[offset++] = 0;
		msg[offset++] = 0;
		msg[offset++] = 42;

		msg[offset++] = 0;
		msg[offset++] = 0;
		msg[offset++] = (byte) 0x80;
		msg[offset++] = 0;

		msg[offset++] = 0;
		msg[offset++] = 0;
		msg[offset++] = (byte) 0x40;
		msg[offset++] = 0;

		channelManager.msgChannelOpen(msg, offset);
		verify(mockTransportConnection).sendAsynchronousMessage(any(byte[].class));
	}
}

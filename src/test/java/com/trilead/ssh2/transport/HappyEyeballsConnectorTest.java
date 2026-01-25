package com.trilead.ssh2.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.trilead.ssh2.IpVersion;

class HappyEyeballsConnectorTest {

	@Test
	void filterByIpVersion_withIpv4Only_returnsOnlyIpv4() throws Exception {
		InetAddress ipv4 = Inet4Address.getByName("127.0.0.1");
		InetAddress ipv6 = Inet6Address.getByName("::1");
		InetAddress[] addresses = { ipv4, ipv6 };

		List<InetAddress> result = HappyEyeballsConnector.filterByIpVersion(addresses, IpVersion.IPV4_ONLY);

		assertEquals(1, result.size());
		assertFalse(result.get(0) instanceof Inet6Address);
	}

	@Test
	void filterByIpVersion_withIpv6Only_returnsOnlyIpv6() throws Exception {
		InetAddress ipv4 = Inet4Address.getByName("127.0.0.1");
		InetAddress ipv6 = Inet6Address.getByName("::1");
		InetAddress[] addresses = { ipv4, ipv6 };

		List<InetAddress> result = HappyEyeballsConnector.filterByIpVersion(addresses, IpVersion.IPV6_ONLY);

		assertEquals(1, result.size());
		assertTrue(result.get(0) instanceof Inet6Address);
	}

	@Test
	void filterByIpVersion_withBoth_returnsAll() throws Exception {
		InetAddress ipv4 = Inet4Address.getByName("127.0.0.1");
		InetAddress ipv6 = Inet6Address.getByName("::1");
		InetAddress[] addresses = { ipv4, ipv6 };

		List<InetAddress> result = HappyEyeballsConnector.filterByIpVersion(addresses, IpVersion.IPV4_AND_IPV6);

		assertEquals(2, result.size());
	}

	@Test
	void filterByIpVersion_withIpv4Only_andNoIpv4Addresses_returnsEmpty() throws Exception {
		InetAddress ipv6 = Inet6Address.getByName("::1");
		InetAddress[] addresses = { ipv6 };

		List<InetAddress> result = HappyEyeballsConnector.filterByIpVersion(addresses, IpVersion.IPV4_ONLY);

		assertTrue(result.isEmpty());
	}

	@Test
	void interleaveByFamily_withMixedAddresses_interleavesCorrectly() throws Exception {
		InetAddress ipv4a = Inet4Address.getByName("127.0.0.1");
		InetAddress ipv4b = Inet4Address.getByName("127.0.0.2");
		InetAddress ipv6a = Inet6Address.getByName("::1");
		InetAddress ipv6b = Inet6Address.getByName("::2");

		List<InetAddress> input = Arrays.asList(ipv4a, ipv4b, ipv6a, ipv6b);
		List<InetAddress> result = HappyEyeballsConnector.interleaveByFamily(input);

		assertEquals(4, result.size());
		// Should be: ipv6a, ipv4a, ipv6b, ipv4b (IPv6 first per RFC 8305)
		assertTrue(result.get(0) instanceof Inet6Address);
		assertFalse(result.get(1) instanceof Inet6Address);
		assertTrue(result.get(2) instanceof Inet6Address);
		assertFalse(result.get(3) instanceof Inet6Address);
	}

	@Test
	void interleaveByFamily_withOnlyIpv4_returnsAllIpv4() throws Exception {
		InetAddress ipv4a = Inet4Address.getByName("127.0.0.1");
		InetAddress ipv4b = Inet4Address.getByName("127.0.0.2");

		List<InetAddress> input = Arrays.asList(ipv4a, ipv4b);
		List<InetAddress> result = HappyEyeballsConnector.interleaveByFamily(input);

		assertEquals(2, result.size());
		assertFalse(result.get(0) instanceof Inet6Address);
		assertFalse(result.get(1) instanceof Inet6Address);
	}

	@Test
	void interleaveByFamily_withUnequalCounts_handlesCorrectly() throws Exception {
		InetAddress ipv4 = Inet4Address.getByName("127.0.0.1");
		InetAddress ipv6a = Inet6Address.getByName("::1");
		InetAddress ipv6b = Inet6Address.getByName("::2");
		InetAddress ipv6c = Inet6Address.getByName("::3");

		List<InetAddress> input = Arrays.asList(ipv4, ipv6a, ipv6b, ipv6c);
		List<InetAddress> result = HappyEyeballsConnector.interleaveByFamily(input);

		assertEquals(4, result.size());
		// Should be: ipv6a, ipv4, ipv6b, ipv6c
		assertTrue(result.get(0) instanceof Inet6Address);
		assertFalse(result.get(1) instanceof Inet6Address);
		assertTrue(result.get(2) instanceof Inet6Address);
		assertTrue(result.get(3) instanceof Inet6Address);
	}

	@Test
	void connect_withSingleAddress_connectsDirectly() throws Exception {
		try (ServerSocket server = new ServerSocket(0)) {
			int port = server.getLocalPort();
			InetAddress addr = InetAddress.getByName("127.0.0.1");

			HappyEyeballsConnector connector = new HappyEyeballsConnector(
					hostname -> new InetAddress[] { addr },
					Socket::new,
					250);

			Thread acceptThread = new Thread(() -> {
				try {
					server.accept().close();
				} catch (IOException ignored) {
				}
			});
			acceptThread.start();

			Socket socket = connector.connect("test.example.com", port, 5000, IpVersion.IPV4_AND_IPV6);

			assertTrue(socket.isConnected());
			socket.close();
			acceptThread.join(1000);
		}
	}

	@Test
	void connect_withNoAddresses_throwsUnknownHostException() {
		HappyEyeballsConnector connector = new HappyEyeballsConnector(
				hostname -> new InetAddress[] {},
				Socket::new,
				250);

		assertThrows(UnknownHostException.class,
				() -> connector.connect("test.example.com", 22, 5000, IpVersion.IPV4_AND_IPV6));
	}

	@Test
	void connect_withDnsFailure_throwsUnknownHostException() {
		HappyEyeballsConnector connector = new HappyEyeballsConnector(
				hostname -> {
					throw new UnknownHostException("DNS failed");
				},
				Socket::new,
				250);

		assertThrows(UnknownHostException.class,
				() -> connector.connect("test.example.com", 22, 5000, IpVersion.IPV4_AND_IPV6));
	}

	@Test
	void connect_withIpv4Only_filtersToIpv4() throws Exception {
		try (ServerSocket server = new ServerSocket(0)) {
			int port = server.getLocalPort();
			InetAddress ipv4 = InetAddress.getByName("127.0.0.1");
			InetAddress ipv6 = Inet6Address.getByName("::1");

			AtomicInteger socketCount = new AtomicInteger(0);

			HappyEyeballsConnector connector = new HappyEyeballsConnector(
					hostname -> new InetAddress[] { ipv6, ipv4 },
					() -> {
						socketCount.incrementAndGet();
						return new Socket();
					},
					250);

			Thread acceptThread = new Thread(() -> {
				try {
					server.accept().close();
				} catch (IOException ignored) {
				}
			});
			acceptThread.start();

			Socket socket = connector.connect("test.example.com", port, 5000, IpVersion.IPV4_ONLY);

			assertTrue(socket.isConnected());
			assertEquals(1, socketCount.get(), "Should only create one socket for single filtered address");
			socket.close();
			acceptThread.join(1000);
		}
	}

	@Test
	void connect_withMultipleAddresses_racesConnections() throws Exception {
		try (ServerSocket server = new ServerSocket(0)) {
			int port = server.getLocalPort();
			InetAddress addr1 = InetAddress.getByName("127.0.0.1");
			InetAddress addr2 = InetAddress.getByName("127.0.0.1");

			List<Socket> createdSockets = new ArrayList<>();

			HappyEyeballsConnector connector = new HappyEyeballsConnector(
					hostname -> new InetAddress[] { addr1, addr2 },
					() -> {
						Socket s = new Socket();
						synchronized (createdSockets) {
							createdSockets.add(s);
						}
						return s;
					},
					50 // Short delay for faster test
			);

			Thread acceptThread = new Thread(() -> {
				try {
					server.accept().close();
				} catch (IOException ignored) {
				}
			});
			acceptThread.start();

			Socket socket = connector.connect("test.example.com", port, 5000, IpVersion.IPV4_AND_IPV6);

			assertTrue(socket.isConnected());
			socket.close();
			acceptThread.join(1000);

			// Give time for cleanup
			Thread.sleep(100);

			// All non-winning sockets should be closed
			synchronized (createdSockets) {
				for (Socket s : createdSockets) {
					if (s != socket) {
						assertTrue(s.isClosed(), "Losing sockets should be closed");
					}
				}
			}
		}
	}

	@Test
	void connect_withAllConnectionsFailing_throwsIOException() throws Exception {
		InetAddress addr1 = InetAddress.getByName("127.0.0.1");
		InetAddress addr2 = InetAddress.getByName("127.0.0.1");

		HappyEyeballsConnector connector = new HappyEyeballsConnector(
				hostname -> new InetAddress[] { addr1, addr2 },
				Socket::new,
				10);

		// Connect to a port that's not listening
		assertThrows(IOException.class, () -> connector.connect("test.example.com", 1, 100, IpVersion.IPV4_AND_IPV6));
	}

	@Test
	void connectionAttemptDelay_isConfigurable() {
		assertEquals(250, HappyEyeballsConnector.CONNECTION_ATTEMPT_DELAY_MS);
	}
}

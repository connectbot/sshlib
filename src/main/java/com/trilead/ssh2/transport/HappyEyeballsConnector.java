package com.trilead.ssh2.transport;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import com.trilead.ssh2.IpVersion;

/**
 * Implements Happy Eyeballs (RFC 8305) connection algorithm.
 *
 * This algorithm improves connection times when both IPv4 and IPv6
 * addresses are available by:
 * <ol>
 * <li>Resolving all addresses (A and AAAA records)</li>
 * <li>Starting IPv6 connection attempts first</li>
 * <li>After a short delay, starting IPv4 attempts in parallel</li>
 * <li>Using whichever connection succeeds first</li>
 * <li>Cancelling/closing remaining attempts</li>
 * </ol>
 */
class HappyEyeballsConnector {

	static final int CONNECTION_ATTEMPT_DELAY_MS = 250;

	private static final ExecutorService EXECUTOR = Executors.newCachedThreadPool(r -> {
		Thread t = new Thread(r, "HappyEyeballs-Connector");
		t.setDaemon(true);
		return t;
	});

	@FunctionalInterface
	interface DnsResolver {
		InetAddress[] resolve(String hostname) throws UnknownHostException;
	}

	@FunctionalInterface
	interface SocketFactory {
		Socket createSocket();
	}

	private final DnsResolver dnsResolver;
	private final SocketFactory socketFactory;
	private final int connectionAttemptDelayMs;

	HappyEyeballsConnector() {
		this(InetAddress::getAllByName, Socket::new, CONNECTION_ATTEMPT_DELAY_MS);
	}

	HappyEyeballsConnector(DnsResolver dnsResolver, SocketFactory socketFactory, int connectionAttemptDelayMs) {
		this.dnsResolver = dnsResolver;
		this.socketFactory = socketFactory;
		this.connectionAttemptDelayMs = connectionAttemptDelayMs;
	}

	/**
	 * Connect to the given hostname and port using Happy Eyeballs algorithm.
	 *
	 * @param hostname       the hostname to connect to
	 * @param port           the port to connect to
	 * @param connectTimeout the connection timeout in milliseconds (0 for infinite)
	 * @param ipVersion      controls which IP versions to use
	 * @return a connected socket
	 * @throws IOException if connection fails
	 */
	Socket connect(String hostname, int port, int connectTimeout, IpVersion ipVersion)
			throws IOException {

		List<InetAddress> addresses = resolveAddresses(hostname, ipVersion);

		if (addresses.isEmpty()) {
			throw new UnknownHostException("No addresses found for: " + hostname);
		}

		if (addresses.size() == 1) {
			return connectSimple(addresses.get(0), port, connectTimeout);
		}

		List<InetAddress> sortedAddresses = interleaveByFamily(addresses);
		return connectWithRacing(sortedAddresses, port, connectTimeout);
	}

	private List<InetAddress> resolveAddresses(String hostname, IpVersion ipVersion)
			throws UnknownHostException {
		InetAddress[] allAddresses = dnsResolver.resolve(hostname);
		return filterByIpVersion(allAddresses, ipVersion);
	}

	static List<InetAddress> filterByIpVersion(InetAddress[] addresses, IpVersion ipVersion) {
		List<InetAddress> filtered = new ArrayList<>();

		for (InetAddress addr : addresses) {
			boolean isIPv6 = addr instanceof Inet6Address;

			if (ipVersion == IpVersion.IPV4_ONLY && isIPv6) {
				continue;
			}
			if (ipVersion == IpVersion.IPV6_ONLY && !isIPv6) {
				continue;
			}
			filtered.add(addr);
		}

		return filtered;
	}

	static List<InetAddress> interleaveByFamily(List<InetAddress> addresses) {
		List<InetAddress> ipv6 = new ArrayList<>();
		List<InetAddress> ipv4 = new ArrayList<>();

		for (InetAddress addr : addresses) {
			if (addr instanceof Inet6Address) {
				ipv6.add(addr);
			} else {
				ipv4.add(addr);
			}
		}

		List<InetAddress> result = new ArrayList<>();
		int maxSize = Math.max(ipv6.size(), ipv4.size());

		for (int i = 0; i < maxSize; i++) {
			if (i < ipv6.size())
				result.add(ipv6.get(i));
			if (i < ipv4.size())
				result.add(ipv4.get(i));
		}

		return result;
	}

	private Socket connectWithRacing(List<InetAddress> addresses, int port, int connectTimeout)
			throws IOException {

		AtomicBoolean winnerFound = new AtomicBoolean(false);
		List<Future<Socket>> futures = new ArrayList<>();
		List<Socket> socketsToClose = new ArrayList<>();

		try {
			for (int i = 0; i < addresses.size(); i++) {
				InetAddress address = addresses.get(i);
				int delay = i * connectionAttemptDelayMs;

				Callable<Socket> task = createConnectionTask(
						address, port, connectTimeout, delay, winnerFound, socketsToClose);
				futures.add(EXECUTOR.submit(task));
			}

			return waitForFirstSuccess(futures);

		} finally {
			for (Future<Socket> future : futures) {
				future.cancel(true);
			}

			synchronized (socketsToClose) {
				for (Socket socket : socketsToClose) {
					closeQuietly(socket);
				}
			}
		}
	}

	private Callable<Socket> createConnectionTask(
			InetAddress address,
			int port,
			int connectTimeout,
			int delay,
			AtomicBoolean winnerFound,
			List<Socket> socketsToClose) {

		return () -> {
			if (delay > 0) {
				Thread.sleep(delay);
			}

			if (winnerFound.get()) {
				throw new CancellationException("Another connection won");
			}

			Socket socket = socketFactory.createSocket();
			synchronized (socketsToClose) {
				socketsToClose.add(socket);
			}

			try {
				socket.connect(new InetSocketAddress(address, port), connectTimeout);
				socket.setSoTimeout(0);

				if (winnerFound.compareAndSet(false, true)) {
					synchronized (socketsToClose) {
						socketsToClose.remove(socket);
					}
					return socket;
				} else {
					closeQuietly(socket);
					throw new CancellationException("Another connection won");
				}
			} catch (IOException e) {
				closeQuietly(socket);
				synchronized (socketsToClose) {
					socketsToClose.remove(socket);
				}
				throw e;
			}
		};
	}

	private Socket waitForFirstSuccess(List<Future<Socket>> futures) throws IOException {
		IOException lastException = null;
		List<Future<Socket>> pending = new ArrayList<>(futures);

		while (!pending.isEmpty()) {
			Future<Socket> completed = null;

			for (Future<Socket> future : pending) {
				if (future.isDone()) {
					completed = future;
					break;
				}
			}

			if (completed == null) {
				try {
					Thread.sleep(10);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					throw new IOException("Connection interrupted", e);
				}
				continue;
			}

			pending.remove(completed);

			try {
				Socket socket = completed.get();
				if (socket != null && socket.isConnected()) {
					return socket;
				}
			} catch (CancellationException e) {
				// Task was cancelled, try next
			} catch (ExecutionException e) {
				Throwable cause = e.getCause();
				if (cause instanceof IOException) {
					lastException = (IOException) cause;
				} else if (cause instanceof InterruptedException) {
					Thread.currentThread().interrupt();
					throw new IOException("Connection interrupted", cause);
				} else {
					lastException = new IOException("Connection failed", cause);
				}
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new IOException("Connection interrupted", e);
			}
		}

		if (lastException != null) {
			throw lastException;
		}
		throw new IOException("All connection attempts failed");
	}

	private Socket connectSimple(InetAddress address, int port, int timeout) throws IOException {
		Socket socket = socketFactory.createSocket();
		try {
			socket.connect(new InetSocketAddress(address, port), timeout);
			socket.setSoTimeout(0);
			return socket;
		} catch (IOException e) {
			closeQuietly(socket);
			throw e;
		}
	}

	private static void closeQuietly(Socket socket) {
		if (socket != null) {
			try {
				socket.close();
			} catch (IOException ignored) {
			}
		}
	}
}

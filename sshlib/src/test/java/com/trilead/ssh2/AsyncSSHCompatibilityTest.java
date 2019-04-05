package com.trilead.ssh2;

import org.apache.commons.io.IOUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Integration tests against OpenSSH.
 *
 * @author Kenny Root
 */
public class AsyncSSHCompatibilityTest {
	private static final Logger logger = LoggerFactory.getLogger(AsyncSSHCompatibilityTest.class.getSimpleName());

	@Rule
	public SshLogger sshLogger = new SshLogger(logger);

	private static final String USERNAME = "user123";
	private static final String PASSWORD = "secretpw";

	@ClassRule
	public static GenericContainer server;

	static {
		ImageFromDockerfile baseImage = new ImageFromDockerfile()
				.withFileFromClasspath("requirements.txt", "asyncssh-server/requirements.txt")
				.withFileFromClasspath("server.py", "asyncssh-server/server.py")
				.withFileFromClasspath("Dockerfile", "asyncssh-server/Dockerfile");
		for (String key : PubkeyConstants.KEY_NAMES) {
			baseImage.withFileFromClasspath(key, "com/trilead/ssh2/crypto/" + key);
		}

		server = new GenericContainer(baseImage)
				.withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("DOCKER"))
				.waitingFor(new LogMessageWaitStrategy()
						.withRegEx(".*LISTENER READY.*\\s"));
	}

	@NotNull
	@Contract("_ -> new")
	private Connection withServer(@NotNull GenericContainer container) {
		return new Connection(container.getContainerIpAddress(), container.getMappedPort(8022));
	}

	private ConnectionInfo assertCanPasswordAuthenticate(GenericContainer server) throws IOException {
		try (Connection c = withServer(server)) {
			c.connect();
			assertThat(c.authenticateWithPassword(USERNAME, PASSWORD), is(true));
			try (Session s = c.openSession()) {
				s.ping();
			}
			return c.getConnectionInfo();
		}
	}

	@Test
	public void canConnectWithPassword() throws Exception {
		assertCanPasswordAuthenticate(server);
	}

	private ConnectionInfo assertCanPubkeyAuthenticate(GenericContainer server, char[] key) throws IOException {
		try (Connection c = withServer(server)) {
			c.connect();
			assertThat(c.authenticateWithPublicKey(USERNAME, key, ""), is(true));
			try (Session s = c.openSession()) {
				s.ping();
			}
			return c.getConnectionInfo();
		}
	}

	private void canConnectWithPubkey(String keyFilename) throws Exception {
		char[] keyChars = IOUtils.toCharArray(getClass().getResourceAsStream("crypto/" + keyFilename), "UTF-8");
		assertCanPubkeyAuthenticate(server, keyChars);
	}

	@Test
	public void canConnectWithEd25519() throws Exception {
		canConnectWithPubkey("ed25519-openssh2-private-key.txt");
	}

	@Test
	public void canConnectWithEcdsa256() throws Exception {
		canConnectWithPubkey("ecdsa-nistp256-openssh2-private-key.txt");
	}

	@Test
	public void canConnectWithEcdsa384() throws Exception {
		canConnectWithPubkey("ecdsa-nistp384-openssh2-private-key.txt");
	}

	@Test
	public void canConnectWithEcdsa521() throws Exception {
		canConnectWithPubkey("ecdsa-nistp521-openssh2-private-key.txt");
	}

	@Test
	public void canConnectWithRsa() throws Exception {
		canConnectWithPubkey("rsa-openssh2-private-key.txt");
	}
}

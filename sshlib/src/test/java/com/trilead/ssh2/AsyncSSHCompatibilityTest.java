package com.trilead.ssh2;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
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
	private final Logger logger = LoggerFactory.getLogger(AsyncSSHCompatibilityTest.class);

	private static final String USERNAME = "user123";
	private static final String PASSWORD = "secretpw";

	@Rule
	public TemporaryFolder hostKeyFolder = new TemporaryFolder();

	private ImageFromDockerfile baseImage = new ImageFromDockerfile()
			.withFileFromClasspath("server.py", "asyncssh-server/server.py")
			.withFileFromClasspath("Dockerfile", "asyncssh-server/Dockerfile");

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
		Slf4jLogConsumer logConsumer = new Slf4jLogConsumer(logger);

		try (GenericContainer server = new GenericContainer(baseImage)) {
			server.withLogConsumer(logConsumer)
					.waitingFor(new LogMessageWaitStrategy()
							.withRegEx("READY\\s")).start();
			assertCanPasswordAuthenticate(server);
		}
	}
}

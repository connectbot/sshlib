package com.trilead.ssh2;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Integration tests against OpenSSH.
 *
 * @author Kenny Root
 */
public class OpenSSHCompatibilityTest {
	private static final String OPTIONS_ENV = "OPTIONS";
	private static final String USERNAME = "testuser";
	private static final String PASSWORD = "testtest123";

	@Rule
	public TemporaryFolder hostKeyFolder = new TemporaryFolder();

	private ImageFromDockerfile baseImage = new ImageFromDockerfile()
			.withFileFromClasspath("run.sh", "openssh-server/run.sh")
			.withFileFromClasspath("Dockerfile", "openssh-server/Dockerfile");

	@NotNull
	@Contract("_ -> new")
	private Connection withServer(@NotNull GenericContainer container) {
		return new Connection(container.getContainerIpAddress(), container.getMappedPort(22));
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

	private void assertCanConnectToServerThatHasKeyType(@NotNull String keyPath, String keyType) throws IOException {
		try (GenericContainer server = new GenericContainer(baseImage)
				.withEnv(OPTIONS_ENV, "-h " + keyPath)) {
			server.start();
			ConnectionInfo info = assertCanPasswordAuthenticate(server);
			assertThat(keyType, is(info.serverHostKeyAlgorithm));
		}
	}

	@Test
	public void canConnectWithPassword() throws Exception {
		try (GenericContainer server = new GenericContainer(baseImage)) {
			server.start();
			assertCanPasswordAuthenticate(server);
		}
	}

	@Test
	public void wrongPasswordFails() throws Exception {
		try (GenericContainer server = new GenericContainer(baseImage)) {
			server.start();
			try (Connection c = withServer(server)) {
				c.connect();
				assertThat(c.authenticateWithPassword(USERNAME, "wrongpassword"), is(false));
			}
		}
	}

	@Test
	public void connectToRsaHost() throws Exception {
		assertCanConnectToServerThatHasKeyType("/etc/ssh/ssh_host_rsa_key", "ssh-rsa");
	}

	@Test
	public void connectToEcdsaHost() throws Exception {
		assertCanConnectToServerThatHasKeyType("/etc/ssh/ssh_host_ecdsa_key", "ecdsa-sha2-nistp256");
	}

	@Test
	public void connectToEd25519Host() throws Exception {
		assertCanConnectToServerThatHasKeyType("/etc/ssh/ssh_host_ed25519_key", "ssh-ed25519");
	}
}

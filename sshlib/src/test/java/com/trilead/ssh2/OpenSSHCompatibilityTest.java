package com.trilead.ssh2;

import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Integration tests against OpenSSH.
 *
 * @author Kenny Root
 */
public class OpenSSHCompatibilityTest {
	private static final String USERNAME = "testuser";
	private static final String PASSWORD = "testtest123";

	@Rule
	public GenericContainer openssh = new GenericContainer(
			new ImageFromDockerfile()
				.withFileFromClasspath("run.sh", "openssh-server/run.sh")
				.withFileFromClasspath("Dockerfile", "openssh-server/Dockerfile")
				);

	@Test
	public void canConnectWithPassword() throws Exception {
		try (Connection c = new Connection(openssh.getContainerIpAddress(), openssh.getMappedPort(22))) {
			c.connect();
			assertTrue("User should be authenticated",
					c.authenticateWithPassword(USERNAME, PASSWORD));
			try (Session s = c.openSession()) {
				s.ping();
			}
		}
	}


	@Test
	public void wrongPasswordFails() throws Exception {
		try (Connection c = new Connection(openssh.getContainerIpAddress(), openssh.getMappedPort(22))) {
			c.connect();
			assertFalse("User should be authenticated",
					c.authenticateWithPassword(USERNAME, "wrongpassword"));
		}
	}
}

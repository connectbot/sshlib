package com.trilead.ssh2;

import org.apache.commons.io.IOUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
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
import java.util.function.Consumer;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Integration tests against Dropbear.
 *
 * @author Kenny Root
 */
public class DropbearCompatibilityTest {
	private static final Logger logger = LoggerFactory.getLogger(DropbearCompatibilityTest.class.getSimpleName());
	private static final Slf4jLogConsumer logConsumer = new Slf4jLogConsumer(logger).withPrefix("DOCKER");

	@Rule
	public SshLogger sshLogger = new SshLogger(logger);

	private static final String OPTIONS_ENV = "OPTIONS";
	private static final String USERNAME = "testuser";
	private static final String PASSWORD = "testtest123";

	private static ImageFromDockerfile baseImage = new ImageFromDockerfile("dropbear-server", false)
			.withFileFromClasspath(".", "dropbear-server");

	static {
		for (String key : PubkeyConstants.KEY_NAMES) {
			baseImage.withFileFromClasspath(key, "com/trilead/ssh2/crypto/" + key);
		}
	}

	@ClassRule
	public static GenericContainer server = getBaseContainer();

	@NotNull
	@Contract("_ -> new")
	private Connection withServer(@NotNull GenericContainer container) {
		return new Connection(container.getContainerIpAddress(), container.getMappedPort(22));
	}

	private static GenericContainer getBaseContainer() {
		return new GenericContainer(baseImage)
				.withExposedPorts(22)
				.withLogConsumer(logConsumer)
				.waitingFor(new LogMessageWaitStrategy()
						.withRegEx(".*Not backgrounding.*\\s"));
	}

	private ConnectionInfo assertCanPasswordAuthenticate(GenericContainer server) throws IOException {
		return assertCanPasswordAuthenticate(server, null);
	}

	private ConnectionInfo assertCanPasswordAuthenticate(GenericContainer server, Consumer<Connection> setupFunc) throws IOException {
		try (Connection c = withServer(server)) {
			if (setupFunc != null) {
				setupFunc.accept(c);
			}
			c.connect();
			assertThat(c.authenticateWithPassword(USERNAME, PASSWORD), is(true));
			try (Session s = c.openSession()) {
				s.ping();
			}
			return c.getConnectionInfo();
		}
	}

	private ConnectionInfo connectToServerWithOptions(@NotNull String options) throws IOException {
		return connectToServerWithOptions(options, null);
	}

	private ConnectionInfo connectToServer(@Nullable Consumer<Connection> setupFunc) throws IOException {
		return assertCanPasswordAuthenticate(server, setupFunc);
	}

	private ConnectionInfo connectToServerWithOptions(@NotNull String options, @Nullable Consumer<Connection> setupFunc) throws IOException {
		try (GenericContainer customServer = getBaseContainer().withEnv(OPTIONS_ENV, options)) {
			customServer.start();
			return assertCanPasswordAuthenticate(customServer, setupFunc);
		}
	}

	private void assertCanConnectToServerThatHasKeyType(@NotNull String keyPath, String keyType) throws IOException {
		ConnectionInfo info = connectToServerWithOptions("-r " + keyPath);
		assertThat(info.serverHostKeyAlgorithm, is(keyType));
	}

	private void canConnectWithPubkey(String keyFilename) throws Exception {
		char[] keyChars = IOUtils.toCharArray(getClass().getResourceAsStream("crypto/" + keyFilename), "UTF-8");

		try (GenericContainer server = getBaseContainer()) {
			server.start();
			try (Connection connection = withServer(server)) {
				connection.connect();
				assertThat(connection.authenticateWithPublicKey(USERNAME, keyChars, ""), is(true));
				try (Session session = connection.openSession()) {
					session.ping();
				}
			}
		}
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

	@Test
	public void canConnectWithPassword() throws Exception {
		try (GenericContainer server = getBaseContainer()) {
			server.start();
			assertCanPasswordAuthenticate(server);
		}
	}

	@Test
	public void wrongPasswordFails() throws Exception {
		try (GenericContainer server = getBaseContainer()) {
			server.start();
			try (Connection c = withServer(server)) {
				c.connect();
				assertThat(c.authenticateWithPassword(USERNAME, "wrongpassword"), is(false));
			}
		}
	}

	@Test
	public void connectToRsaHost() throws Exception {
		assertCanConnectToServerThatHasKeyType("/etc/dropbear/dropbear_rsa_host_key", "rsa-sha2-256");
	}

	@Test
	public void connectToEcdsaHost() throws Exception {
		assertCanConnectToServerThatHasKeyType("/etc/dropbear/dropbear_ecdsa_host_key", "ecdsa-sha2-nistp256");
	}

	private void assertCanConnectToServerWithKex(@NotNull String kexType) throws IOException {
		ConnectionInfo info = connectToServer(
				c -> c.setKeyExchangeAlgorithms(new String[]{kexType}));
		assertThat(info.keyExchangeAlgorithm, is(kexType));
	}

	@Test
	public void canConnectWithKexCurve25519LibsshOrg() throws Exception {
		assertCanConnectToServerWithKex("curve25519-sha256@libssh.org");
	}

	@Test
	public void canConnectWithKexCurve25519() throws Exception {
		assertCanConnectToServerWithKex("curve25519-sha256");
	}

	@Test
	public void canConnectWithKexDHGroup14() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group14-sha1");
	}

	@Test
	public void canConnectWithKexDHGroup14Sha256() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group14-sha256");
	}

	@Test
	public void canConnectWithKexEcdhSha2Nistp256() throws Exception {
		assertCanConnectToServerWithKex("ecdh-sha2-nistp256");
	}

	@Test
	public void canConnectWithKexEcdhSha2Nistp384() throws Exception {
		assertCanConnectToServerWithKex("ecdh-sha2-nistp384");
	}

	@Test
	public void canConnectWithKexEcdhSha2Nistp521() throws Exception {
		assertCanConnectToServerWithKex("ecdh-sha2-nistp521");
	}

	private void setCiphers(Connection c, String cipher) {
		c.setClient2ServerCiphers(new String[]{cipher});
		c.setServer2ClientCiphers(new String[]{cipher});
	}

	private void assertCanConnectToServerWithCipher(@NotNull String cipher) throws IOException {
		ConnectionInfo info = connectToServer(c -> setCiphers(c, cipher));
		assertThat(info.clientToServerCryptoAlgorithm, is(cipher));
		assertThat(info.serverToClientCryptoAlgorithm, is(cipher));
	}

	@Test
	public void canConnectWithCipherAes128Ctr() throws Exception {
		assertCanConnectToServerWithCipher("aes128-ctr");
	}

	@Test
	public void canConnectWithCipherAes256Ctr() throws Exception {
		assertCanConnectToServerWithCipher("aes256-ctr");
	}

	private void setMac(Connection c, String mac) {
		c.setClient2ServerMACs(new String[]{mac});
		c.setServer2ClientMACs(new String[]{mac});
	}

	private void assertCanConnectToServerWithMac(@NotNull String mac) throws IOException {
		ConnectionInfo info = connectToServer(c -> setMac(c, mac));
		assertThat(info.clientToServerMACAlgorithm, is(mac));
		assertThat(info.serverToClientMACAlgorithm, is(mac));
	}

	@Test
	public void canConnectWithMacHmacSha1() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha1");
	}

	@Test
	public void canConnectWithMacHmacSha2_256() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha2-256");
	}

	@Test
	public void canConnectWithCompression() throws Exception {
		try (GenericContainer customServer = getBaseContainer()) {
			customServer.start();
			try (Connection c = withServer(customServer)) {
				c.setCompression(true);
				c.connect();
				assertThat(c.authenticateWithPassword(USERNAME, PASSWORD), is(true));
				try (Session s = c.openSession()) {
					s.ping();
				}

				ConnectionInfo info = c.getConnectionInfo();
				assertThat(info.clientToServerCompressionAlgorithm, is("zlib@openssh.com"));
				assertThat(info.serverToClientCompressionAlgorithm, is("zlib@openssh.com"));
			}
		}
	}

	private void canConnectWithHostKeyAlgorithm(String keyPath, String hostKeyAlgorithm) throws Exception {
		ConnectionInfo info = connectToServerWithOptions("-r " + keyPath, c -> c.setServerHostKeyAlgorithms(new String[]{hostKeyAlgorithm}));
		assertThat(info.serverHostKeyAlgorithm, is(hostKeyAlgorithm));
	}

	@Test
	public void canConnectToHostWithHostKeySshRsa() throws Exception {
		canConnectWithHostKeyAlgorithm("/etc/dropbear/dropbear_rsa_host_key", "ssh-rsa");
	}
}

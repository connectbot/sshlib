package com.trilead.ssh2;

import org.apache.commons.io.IOUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
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
	private static final Logger logger = LoggerFactory.getLogger(AsyncSSHCompatibilityTest.class);
	private static final Slf4jLogConsumer logConsumer = new Slf4jLogConsumer(logger);

	private static final String OPTIONS_ENV = "OPTIONS";
	private static final String USERNAME = "testuser";
	private static final String PASSWORD = "testtest123";

	private static ImageFromDockerfile baseImage;

	static {
		baseImage = new ImageFromDockerfile()
				.withFileFromClasspath("run.sh", "openssh-server/run.sh")
				.withFileFromClasspath("Dockerfile", "openssh-server/Dockerfile");
		for (String key : PubkeyConstants.KEY_NAMES) {
			baseImage.withFileFromClasspath(key, "com/trilead/ssh2/crypto/" + key);
		}
	}

	@NotNull
	@Contract("_ -> new")
	private Connection withServer(@NotNull GenericContainer container) {
		return new Connection(container.getContainerIpAddress(), container.getMappedPort(22));
	}

	private GenericContainer getBaseContainer() {
		GenericContainer container = new GenericContainer(baseImage);
		container.withLogConsumer(logConsumer);
		return container;
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

	private ConnectionInfo connectToServerWithOptions(@NotNull String options) throws IOException {
		try (GenericContainer server = new GenericContainer(baseImage)
				.withEnv(OPTIONS_ENV, options)) {
			server.start();
			return assertCanPasswordAuthenticate(server);
		}
	}

	private void assertCanConnectToServerThatHasKeyType(@NotNull String keyPath, String keyType) throws IOException {
		ConnectionInfo info = connectToServerWithOptions("-h " + keyPath);
		assertThat(keyType, is(info.serverHostKeyAlgorithm));
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

	private void assertCanConnectToServerWithKex(@NotNull String kexType) throws IOException {
		ConnectionInfo info = connectToServerWithOptions("-oKexAlgorithms=" + kexType);
		assertThat(kexType, is(info.keyExchangeAlgorithm));
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
	public void canConnectWithKexDHGroup1() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group1-sha1");
	}

	@Test
	public void canConnectWithKexDHGroup14() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group14-sha1");
	}

	@Test
	public void canConnectWithKexDHGroupExchangeSha1() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group-exchange-sha1");
	}

	@Test
	public void canConnectWithKexDHGroupExchangeSha256() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group-exchange-sha256");
	}

	@Test
	public void canConnectWithKexDHGroup14Sha256() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group14-sha256");
	}

	@Test
	public void canConnectWithKexDHGroup16Sha512() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group16-sha512");
	}

	@Test
	public void canConnectWithKexDHGroup18Sha512() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group18-sha512");
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

	private void assertCanConnectToServerWithCipher(@NotNull String ciphers) throws IOException {
		ConnectionInfo info = connectToServerWithOptions("-oCiphers=" + ciphers);
		assertThat(ciphers, is(info.clientToServerCryptoAlgorithm));
		assertThat(ciphers, is(info.serverToClientCryptoAlgorithm));
	}

	@Test
	public void canConnectWithCipherAes128Ctr() throws Exception {
		assertCanConnectToServerWithCipher("aes128-ctr");
	}

	@Test
	public void canConnectWithCipherAes256Ctr() throws Exception {
		assertCanConnectToServerWithCipher("aes256-ctr");
	}

	@Test
	public void canConnectWithCipherAes128Cbc() throws Exception {
		assertCanConnectToServerWithCipher("aes128-cbc");
	}

	@Test
	public void canConnectWithCipherAes256Cbc() throws Exception {
		assertCanConnectToServerWithCipher("aes256-cbc");
	}

	@Test
	public void canConnectWithCipher3desCbc() throws Exception {
		assertCanConnectToServerWithCipher("3des-cbc");
	}

	private void assertCanConnectToServerWithMac(@NotNull String macs) throws IOException {
		ConnectionInfo info = connectToServerWithOptions("-oMACs=" + macs);
		assertThat(macs, is(info.clientToServerMACAlgorithm));
		assertThat(macs, is(info.serverToClientMACAlgorithm));
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
	public void canConnectWithMacHmacSha2_512() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha2-512");
	}

	@Test
	public void canConnectWithMacHmacSha1Etm() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha1-etm@openssh.com");
	}

	@Test
	public void canConnectWithMacHmacSha2_256Etm() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha2-256-etm@openssh.com");
	}

	@Test
	public void canConnectWithMacHmacSha2_512Etm() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha2-512-etm@openssh.com");
	}

	@Test
	public void canConnectWithCompression() throws Exception {
		try (GenericContainer server = getBaseContainer()
				.withEnv(OPTIONS_ENV, "-oCompression=yes")) {
			server.start();
			try (Connection c = withServer(server)) {
				c.setCompression(true);
				c.connect();
				assertThat(c.authenticateWithPassword(USERNAME, PASSWORD), is(true));
				try (Session s = c.openSession()) {
					s.ping();
				}

				ConnectionInfo info = c.getConnectionInfo();
				assertThat("zlib@openssh.com", is(info.clientToServerCompressionAlgorithm));
				assertThat("zlib@openssh.com", is(info.serverToClientCompressionAlgorithm));
			}
		}
	}
}

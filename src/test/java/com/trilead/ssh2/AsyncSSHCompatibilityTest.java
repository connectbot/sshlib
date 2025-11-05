package com.trilead.ssh2;

import org.apache.commons.io.IOUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.util.function.Consumer;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Integration tests against AsyncSSH.
 *
 * @author Kenny Root
 */
@Testcontainers
public class AsyncSSHCompatibilityTest {
	private static final Logger logger = LoggerFactory.getLogger(AsyncSSHCompatibilityTest.class.getSimpleName());

	@RegisterExtension
	public SshLogger sshLogger = new SshLogger(logger);

	private static final String USERNAME = "user123";
	private static final String PASSWORD = "secretpw";

	private static ImageFromDockerfile baseImage = new ImageFromDockerfile("asyncssh-server", false)
			.withFileFromClasspath(".", "asyncssh-server");

	static {
		for (String key : PubkeyConstants.KEY_NAMES) {
			baseImage.withFileFromClasspath(key, "com/trilead/ssh2/crypto/" + key);
		}
	}

	@Container
	public static GenericContainer<?> server = getServer(baseImage);

	@SuppressWarnings("resource")
	private static GenericContainer<?> getServer(ImageFromDockerfile baseImage) {
		return new GenericContainer<>(baseImage)
				.withExposedPorts(8022)
				.withLogConsumer(new Slf4jLogConsumer(logger).withPrefix("DOCKER"))
				.waitingFor(new LogMessageWaitStrategy()
						.withRegEx(".*LISTENER READY.*\\s"));
	}

	@NotNull
	@Contract("_ -> new")
	private Connection withServer(@NotNull GenericContainer<?> container) {
		return new Connection(container.getHost(), container.getMappedPort(8022));
	}

	private ConnectionInfo assertCanPasswordAuthenticate(GenericContainer<?> server, Consumer<Connection> setupFunc)
			throws IOException {
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

	@Test
	public void canConnectWithPassword() throws Exception {
		assertCanPasswordAuthenticate(server, null);
	}

	private ConnectionInfo connectToServer(@Nullable Consumer<Connection> setupFunc) throws IOException {
		return assertCanPasswordAuthenticate(server, setupFunc);
	}

	private ConnectionInfo assertCanPubkeyAuthenticate(GenericContainer<?> server, char[] key) throws IOException {
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

	private void assertCanConnectToServerWithKex(@NotNull String kexType) throws IOException {
		ConnectionInfo info = connectToServer(
				c -> c.setKeyExchangeAlgorithms(new String[] { kexType }));
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
		c.setClient2ServerCiphers(new String[] { cipher });
		c.setServer2ClientCiphers(new String[] { cipher });
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

	@Test
	public void canConnectWithCipherChacha20Poly1305() throws Exception {
		assertCanConnectToServerWithCipher("chacha20-poly1305@openssh.com");
	}

	@Test
	public void canConnectWithCipherAes128Gcm() throws Exception {
		assertCanConnectToServerWithCipher("aes128-gcm@openssh.com");
	}

	@Test
	public void canConnectWithCipherAes256Gcm() throws Exception {
		assertCanConnectToServerWithCipher("aes256-gcm@openssh.com");
	}

	private void setMac(Connection c, String mac) {
		// This is needed because AEAD selection would result in null MAC.
		setCiphers(c, "aes128-ctr");

		c.setClient2ServerMACs(new String[] { mac });
		c.setServer2ClientMACs(new String[] { mac });
	}

	private void assertCanConnectToServerWithMac(@NotNull String mac) throws IOException {
		ConnectionInfo info = connectToServer(c -> setMac(c, mac));
		assertThat(info.clientToServerMACAlgorithm, is(mac));
		assertThat(info.serverToClientMACAlgorithm, is(mac));
	}

	@Test
	public void canConnectWithMacHmacSha2_256() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha2-256");
	}
}

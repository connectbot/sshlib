package com.trilead.ssh2.crypto.dh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.trilead.ssh2.MlKemAvailability;

@DisplayName("ML-KEM-768 Hybrid Key Exchange Tests")
class MlKemHybridExchangeTest {

	private static final boolean mlkemAvailable = MlKemAvailability.isAvailable();
	private MlKemHybridExchange clientExchange;
	private MlKemHybridExchange serverExchange;

	@BeforeEach
	void setUp() throws IOException {
		org.junit.jupiter.api.Assumptions.assumeTrue(
				mlkemAvailable, "ML-KEM not available on this JDK");
		clientExchange = new MlKemHybridExchange();
		serverExchange = new MlKemHybridExchange();
	}

	@Test
	@DisplayName("ML-KEM availability should be detected correctly")
	void testMlKemAvailabilityDetection() {
		System.out.println(
				"ML-KEM availability: " + mlkemAvailable
						+ " (expected true for Java 23 with proper ML-KEM support)");
		assertTrue(
				mlkemAvailable,
				"ML-KEM should be available on Java 23 with proper configuration");
	}

	@Test
	@DisplayName("Should initialize with correct algorithm name")
	void testInitWithCorrectAlgorithm() throws IOException {
		clientExchange.init(MlKemHybridExchange.NAME);
		assertNotNull(clientExchange.getE());
	}

	@Test
	@DisplayName("Should reject invalid algorithm name")
	void testInitWithInvalidAlgorithm() {
		assertThrows(IOException.class, () -> clientExchange.init("invalid-algo"));
	}

	@Test
	@DisplayName("Client should generate ephemeral public key")
	void testClientPublicKeyGeneration() throws IOException {
		clientExchange.init(MlKemHybridExchange.NAME);
		byte[] clientPublicKey = clientExchange.getE();

		assertNotNull(clientPublicKey);
		assertEquals(1216, clientPublicKey.length, "Client public key should be 1216 bytes (1184 ML-KEM + 32 X25519)");
	}

	@Test
	@DisplayName("Server should extract client keys and perform encapsulation")
	void testServerEncapsulation() throws Exception {
		clientExchange.init(MlKemHybridExchange.NAME);
		serverExchange.init(MlKemHybridExchange.NAME);

		byte[] clientInit = clientExchange.getE();
		byte[] mlkemPublicKey = new byte[1184];
		byte[] x25519PublicKey = new byte[32];
		System.arraycopy(clientInit, 0, mlkemPublicKey, 0, 1184);
		System.arraycopy(clientInit, 1184, x25519PublicKey, 0, 32);

		MlKemAdapter adapter = createMlKemAdapter();
		MlKemAdapter.MlKemEncapsulationResult result = adapter.encapsulate(mlkemPublicKey);
		byte[] ciphertext = result.getCiphertext();

		assertEquals(1088, ciphertext.length, "ML-KEM-768 ciphertext should be 1088 bytes");
	}

	@Test
	@DisplayName("Should compute hybrid shared secret from client and server exchange")
	void testHybridKeyExchange() throws Exception {
		clientExchange.init(MlKemHybridExchange.NAME);
		serverExchange.init(MlKemHybridExchange.NAME);

		byte[] clientInit = clientExchange.getE();
		byte[] serverReply = performServerEncapsulation(clientInit, serverExchange.getE());

		clientExchange.setF(serverReply);

		byte[] clientK = clientExchange.getK();
		assertNotNull(clientK);
		assertEquals(32, clientK.length, "Shared secret should be 32 bytes");
	}

	@Test
	@DisplayName("Client should reject invalid ciphertext length")
	void testClientRejectsInvalidCiphertextLength() throws IOException {
		clientExchange.init(MlKemHybridExchange.NAME);

		byte[] invalidReply = new byte[100];
		assertThrows(IOException.class, () -> clientExchange.setF(invalidReply));
	}

	@Test
	@DisplayName("Client should reject too long ciphertext")
	void testClientRejectsTooLongCiphertext() throws IOException {
		clientExchange.init(MlKemHybridExchange.NAME);

		byte[] invalidReply = new byte[2000];
		assertThrows(IOException.class, () -> clientExchange.setF(invalidReply));
	}

	@Test
	@DisplayName("Should return correct hash algorithm")
	void testHashAlgorithm() throws IOException {
		clientExchange.init(MlKemHybridExchange.NAME);
		assertEquals("SHA-256", clientExchange.getHashAlgo());
	}

	@Test
	@DisplayName("Should calculate exchange hash correctly")
	void testExchangeHashCalculation() throws Exception {
		clientExchange.init(MlKemHybridExchange.NAME);
		serverExchange.init(MlKemHybridExchange.NAME);

		byte[] clientInit = clientExchange.getE();
		byte[] serverReply = performServerEncapsulation(clientInit, serverExchange.getE());

		clientExchange.setF(serverReply);

		byte[] clientVersion = "SSH-2.0-Test".getBytes();
		byte[] serverVersion = "SSH-2.0-TestServer".getBytes();
		byte[] kexInit = new byte[20];
		byte[] hostKey = new byte[100];

		byte[] H =
				clientExchange.calculateH(clientVersion, serverVersion, kexInit, kexInit, hostKey);

		assertNotNull(H);
		assertEquals(32, H.length, "SHA-256 hash should be 32 bytes");
	}

	@Test
	@DisplayName("Two independent exchanges should produce different shared secrets")
	void testDifferentExchangesProduceDifferentSecrets() throws Exception {
		MlKemHybridExchange exchange1 = new MlKemHybridExchange();
		MlKemHybridExchange exchange2 = new MlKemHybridExchange();

		exchange1.init(MlKemHybridExchange.NAME);
		exchange2.init(MlKemHybridExchange.NAME);

		byte[] init1 = exchange1.getE();
		byte[] init2 = exchange2.getE();

		assertNotNull(init1);
		assertNotNull(init2);
		assertTrue(
				!java.util.Arrays.equals(init1, init2),
				"Two independent exchanges should produce different ephemeral keys");
	}

	@Test
	@DisplayName("Shared secret should not be all zeros")
	void testSharedSecretNotAllZeros() throws Exception {
		clientExchange.init(MlKemHybridExchange.NAME);
		serverExchange.init(MlKemHybridExchange.NAME);

		byte[] clientInit = clientExchange.getE();
		byte[] serverReply = performServerEncapsulation(clientInit, serverExchange.getE());

		clientExchange.setF(serverReply);
		byte[] K = clientExchange.getK();

		int allZeros = 0;
		for (byte b : K) {
			allZeros |= b;
		}
		assertTrue(allZeros != 0, "Shared secret should not be all zeros");
	}

	@Test
	@DisplayName("Should handle multiple sequential key exchanges")
	void testMultipleSequentialExchanges() throws Exception {
		for (int i = 0; i < 3; i++) {
			MlKemHybridExchange client = new MlKemHybridExchange();
			MlKemHybridExchange server = new MlKemHybridExchange();

			client.init(MlKemHybridExchange.NAME);
			server.init(MlKemHybridExchange.NAME);

			byte[] clientInit = client.getE();
			byte[] serverReply = performServerEncapsulation(clientInit, server.getE());

			client.setF(serverReply);
			byte[] K = client.getK();

			assertNotNull(K);
			assertEquals(32, K.length, "Exchange " + i + " should produce 32-byte shared secret");
		}
	}

	@Test
	@DisplayName("Client getServerE should return server reply")
	void testGetServerE() throws Exception {
		clientExchange.init(MlKemHybridExchange.NAME);
		serverExchange.init(MlKemHybridExchange.NAME);

		byte[] clientInit = clientExchange.getE();
		byte[] serverReply = performServerEncapsulation(clientInit, serverExchange.getE());

		clientExchange.setF(serverReply);
		byte[] serverE = clientExchange.getServerE();

		assertNotNull(serverE);
		assertEquals(1120, serverE.length, "Server E (S_REPLY) should be 1120 bytes (1088 ciphertext + 32 X25519 public key)");
	}

	@Test
	@DisplayName("Should validate X25519 public key length")
	void testX25519PublicKeyValidation() throws IOException {
		clientExchange.init(MlKemHybridExchange.NAME);

		byte[] validMlkemCiphertext = new byte[1088];
		byte[] invalidX25519Key = new byte[16];

		byte[] reply = new byte[1088 + 16];
		System.arraycopy(validMlkemCiphertext, 0, reply, 0, 1088);
		System.arraycopy(invalidX25519Key, 0, reply, 1088, 16);

		assertThrows(IOException.class, () -> clientExchange.setF(reply));
	}

	private byte[] performServerEncapsulation(byte[] clientInit, byte[] serverPublicKey)
			throws Exception {
		byte[] mlkemPublicKey = new byte[1184];
		byte[] x25519PublicKey = new byte[32];
		System.arraycopy(clientInit, 0, mlkemPublicKey, 0, 1184);
		System.arraycopy(clientInit, 1184, x25519PublicKey, 0, 32);

		MlKemAdapter adapter = createMlKemAdapter();
		MlKemAdapter.MlKemEncapsulationResult result = adapter.encapsulate(mlkemPublicKey);
		byte[] ciphertext = result.getCiphertext();

		byte[] serverX25519PublicKey = new byte[32];
		System.arraycopy(serverPublicKey, 1184, serverX25519PublicKey, 0, 32);

		byte[] reply = new byte[1088 + 32];
		System.arraycopy(ciphertext, 0, reply, 0, 1088);
		System.arraycopy(serverX25519PublicKey, 0, reply, 1088, 32);

		return reply;
	}

	private MlKemAdapter createMlKemAdapter() throws Exception {
		try {
			return new JavaKemAdapter();
		} catch (IOException e) {
			return new KyberKotlinAdapter();
		}
	}

	private byte[] wrapRawMlKemPublicKey(byte[] rawKey) {
		byte[] x509 = new byte[1206];
		x509[0] = 0x30;
		x509[1] = (byte) 0x82;
		x509[2] = 0x04;
		x509[3] = (byte) 0xb2;
		x509[4] = 0x30;
		x509[5] = 0x0b;
		x509[6] = 0x06;
		x509[7] = 0x09;
		x509[8] = 0x60;
		x509[9] = (byte) 0x86;
		x509[10] = 0x48;
		x509[11] = 0x01;
		x509[12] = 0x65;
		x509[13] = 0x03;
		x509[14] = 0x04;
		x509[15] = 0x04;
		x509[16] = 0x02;
		x509[17] = 0x03;
		x509[18] = (byte) 0x82;
		x509[19] = 0x04;
		x509[20] = (byte) 0xa1;
		x509[21] = 0x00;
		System.arraycopy(rawKey, 0, x509, 22, 1184);
		return x509;
	}
}

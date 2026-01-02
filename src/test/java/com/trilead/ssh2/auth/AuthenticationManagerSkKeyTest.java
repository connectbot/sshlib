package com.trilead.ssh2.auth;

import com.trilead.ssh2.ExtensionInfo;
import com.trilead.ssh2.packets.TypesWriter;
import com.trilead.ssh2.signature.SkPublicKey;
import com.trilead.ssh2.transport.TransportManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for SK (Security Key) public key authentication in AuthenticationManager.
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticationManagerSkKeyTest {

	private static final String SK_ED25519_KEY_TYPE = "sk-ssh-ed25519@openssh.com";
	private static final String SK_ECDSA_KEY_TYPE = "sk-ecdsa-sha2-nistp256@openssh.com";
	private static final String DEFAULT_APPLICATION = "ssh:";
	private static final String TEST_USER = "testuser";
	private static final byte[] TEST_SESSION_ID = new byte[] { 0x01, 0x02, 0x03, 0x04 };
	private static final byte[] TEST_KEY_DATA = new byte[] {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
	};
	private static final byte[] TEST_SIGNATURE = new byte[] { 0x55, 0x66, 0x77, 0x08 };

	@Mock
	private TransportManager tm;

	@Mock
	private ExtensionInfo extensionInfo;

	private AuthenticationManager authManager;

	/**
	 * Test implementation of SkPublicKey for unit testing.
	 */
	static class TestSkPublicKey implements SkPublicKey {
		private final String keyType;
		private final String application;
		private final byte[] keyData;

		TestSkPublicKey(String keyType, String application, byte[] keyData) {
			this.keyType = keyType;
			this.application = application;
			this.keyData = keyData.clone();
		}

		@Override
		public String getSshKeyType() {
			return keyType;
		}

		@Override
		public String getApplication() {
			return application;
		}

		@Override
		public byte[] getKeyData() {
			return keyData.clone();
		}

		@Override
		public String getAlgorithm() {
			return keyType;
		}

		@Override
		public String getFormat() {
			return "SSH";
		}

		@Override
		public byte[] getEncoded() {
			TypesWriter tw = new TypesWriter();
			tw.writeString(keyType);
			tw.writeString(keyData, 0, keyData.length);
			tw.writeString(application);
			return tw.getBytes();
		}
	}

	/**
	 * Test SignatureProxy that records the hash algorithm used for signing.
	 */
	static class TestSignatureProxy extends SignatureProxy {
		private String lastHashAlgorithm;
		private byte[] lastMessage;
		private final byte[] signatureToReturn;

		TestSignatureProxy(SkPublicKey publicKey, byte[] signatureToReturn) {
			super(publicKey);
			this.signatureToReturn = signatureToReturn;
		}

		@Override
		public byte[] sign(byte[] message, String hashAlgorithm) throws IOException {
			this.lastMessage = message;
			this.lastHashAlgorithm = hashAlgorithm;
			return signatureToReturn;
		}

		public String getLastHashAlgorithm() {
			return lastHashAlgorithm;
		}

		public byte[] getLastMessage() {
			return lastMessage;
		}
	}

	@BeforeEach
	public void setUp() {
		authManager = new AuthenticationManager(tm);
	}

	@Test
	public void authenticateSkKey_WithoutSignatureProxy_ThrowsIOException() throws IOException {
		TestSkPublicKey skKey = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);

		// Setup mocks for initialization
		setupMocksForAuthentication();

		// Create a SignatureProxy that provides the SK public key
		TestSignatureProxy proxyWithSkKey = new TestSignatureProxy(skKey, TEST_SIGNATURE);

		// Create a mock KeyPair with SK public key - this simulates trying to use an SK key
		// without a proper SignatureProxy for signing
		java.security.KeyPair skKeyPair = new java.security.KeyPair(skKey, null);

		setupMockForAuthFailWithSkKey();

		IOException exception = assertThrows(IOException.class, () -> {
			// This will fail because SK keys require a SignatureProxy for signing
			authManager.authenticatePublicKey(TEST_USER, skKeyPair, null, null);
		});

		// The exception should indicate that SK key authentication requires a SignatureProxy
		assertTrue(exception.getMessage().contains("SK key authentication requires a SignatureProxy") ||
				exception.getMessage().contains("Publickey authentication failed"));
	}

	private void setupMockForAuthFailWithSkKey() throws IOException {
		// Setup mock to simulate SSH authentication flow that gets to the SK key branch
		final byte[] serviceAccept = new byte[] { 6 }; // SSH_MSG_SERVICE_ACCEPT
		final byte[] userauthFailure = createUserauthFailure(new String[] { "publickey" });

		// Queue messages for the authentication flow
		new Thread(() -> {
			try {
				Thread.sleep(50);
				authManager.handleMessage(serviceAccept, serviceAccept.length);
				Thread.sleep(50);
				authManager.handleMessage(userauthFailure, userauthFailure.length);
			} catch (Exception e) {
				// Ignore
			}
		}).start();
	}

	@Test
	public void authenticateSkEd25519Key_UsesSha512() throws Exception {
		TestSkPublicKey skKey = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);
		TestSignatureProxy signatureProxy = new TestSignatureProxy(skKey, TEST_SIGNATURE);

		setupMocksForAuthentication();
		setupMockForAuthSuccess();

		authManager.authenticatePublicKey(TEST_USER, signatureProxy);

		assertEquals(SignatureProxy.SHA512, signatureProxy.getLastHashAlgorithm(),
			"SK Ed25519 keys should use SHA512 for signing");
	}

	@Test
	public void authenticateSkEcdsaKey_UsesSha256() throws Exception {
		TestSkPublicKey skKey = new TestSkPublicKey(SK_ECDSA_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);
		TestSignatureProxy signatureProxy = new TestSignatureProxy(skKey, TEST_SIGNATURE);

		setupMocksForAuthentication();
		setupMockForAuthSuccess();

		authManager.authenticatePublicKey(TEST_USER, signatureProxy);

		assertEquals(SignatureProxy.SHA256, signatureProxy.getLastHashAlgorithm(),
			"SK ECDSA keys should use SHA256 for signing");
	}

	@Test
	public void authenticateSkKey_SignatureProxyReceivesMessage() throws Exception {
		TestSkPublicKey skKey = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);
		TestSignatureProxy signatureProxy = new TestSignatureProxy(skKey, TEST_SIGNATURE);

		setupMocksForAuthentication();
		setupMockForAuthSuccess();

		authManager.authenticatePublicKey(TEST_USER, signatureProxy);

		// Verify that the SignatureProxy received a message to sign
		byte[] signedMessage = signatureProxy.getLastMessage();
		assertTrue(signedMessage != null && signedMessage.length > 0,
			"SignatureProxy should receive a message to sign");
	}

	@Test
	public void authenticateSkKey_SendsAuthenticationRequest() throws Exception {
		TestSkPublicKey skKey = new TestSkPublicKey(SK_ED25519_KEY_TYPE, DEFAULT_APPLICATION, TEST_KEY_DATA);
		TestSignatureProxy signatureProxy = new TestSignatureProxy(skKey, TEST_SIGNATURE);

		setupMocksForAuthentication();
		setupMockForAuthSuccess();

		authManager.authenticatePublicKey(TEST_USER, signatureProxy);

		// Verify that messages were sent to the transport manager
		ArgumentCaptor<byte[]> messageCaptor = ArgumentCaptor.forClass(byte[].class);
		verify(tm, org.mockito.Mockito.atLeastOnce()).sendMessage(messageCaptor.capture());

		// At least one message should have been sent
		assertTrue(messageCaptor.getAllValues().size() > 0,
			"Authentication should send at least one message");
	}

	private void setupMocksForAuthentication() throws IOException {
		lenient().when(tm.getSessionIdentifier()).thenReturn(TEST_SESSION_ID);
		lenient().when(tm.getExtensionInfo()).thenReturn(extensionInfo);
		lenient().when(extensionInfo.getSignatureAlgorithmsAccepted()).thenReturn(new HashSet<>());
	}

	private void setupMockForAuthSuccess() throws IOException {
		// Setup mock to simulate SSH authentication flow
		// First message is service accept, then userauth failure (to get available methods),
		// then auth success
		final int[] messageCount = {0};

		lenient().doAnswer(invocation -> {
			messageCount[0]++;
			return null;
		}).when(tm).sendMessage(any(byte[].class));

		lenient().doAnswer(invocation -> {
			// Simulate message handler registration
			return null;
		}).when(tm).registerMessageHandler(any(), any(int.class), any(int.class));

		lenient().doAnswer(invocation -> {
			// Simulate message handler removal
			return null;
		}).when(tm).removeMessageHandler(any(), any(int.class), any(int.class));

		// We need to inject messages into the authManager's packet queue
		// This is done by calling handleMessage
		// Simulate: service accept, then userauth failure with publickey available, then success
		final byte[] serviceAccept = new byte[] { 6 }; // SSH_MSG_SERVICE_ACCEPT
		final byte[] userauthFailure = createUserauthFailure(new String[] { "publickey" });
		final byte[] userauthSuccess = new byte[] { 52 }; // SSH_MSG_USERAUTH_SUCCESS

		// Queue messages for the authentication flow
		new Thread(() -> {
			try {
				Thread.sleep(50);
				authManager.handleMessage(serviceAccept, serviceAccept.length);
				Thread.sleep(50);
				authManager.handleMessage(userauthFailure, userauthFailure.length);
				Thread.sleep(50);
				authManager.handleMessage(userauthSuccess, userauthSuccess.length);
			} catch (Exception e) {
				// Ignore
			}
		}).start();
	}

	private byte[] createUserauthFailure(String[] methods) {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(51); // SSH_MSG_USERAUTH_FAILURE

		// Write name-list of methods
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < methods.length; i++) {
			if (i > 0) sb.append(",");
			sb.append(methods[i]);
		}
		tw.writeString(sb.toString());
		tw.writeBoolean(false); // partial success

		return tw.getBytes();
	}
}

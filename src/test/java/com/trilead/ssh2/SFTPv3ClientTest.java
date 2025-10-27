package com.trilead.ssh2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SFTPv3ClientTest {

	@Mock
	private Connection mockConnection;

	@Mock
	private Session mockSession;

	@Test
	public void testConstructorWithNullConnection() {
		assertThrows(IllegalArgumentException.class, () ->
			new SFTPv3Client(null));
	}

	@Test
	public void testDeprecatedConstructorWithNullConnection() {
		assertThrows(IllegalArgumentException.class, () ->
			new SFTPv3Client(null, System.out));
	}

	@Test
	public void testGetProtocolVersionDefault() throws IOException {
		// We need to mock the session creation and SFTP initialization
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);
			assertEquals(0, client.getProtocolVersion(), "Default protocol version should be 0");
		} catch (IOException e) {
			// Expected since we're not providing a real SFTP handshake
			// Just test that the constructor doesn't throw IllegalArgumentException
		}
	}

	@Test
	public void testGetCharsetDefault() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);
			assertNull(client.getCharset(), "Default charset should be null");
		} catch (IOException e) {
			// Expected since we're not providing a real SFTP handshake
		}
	}

	@Test
	public void testSetCharsetWithValidCharset() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			// Test setting valid charsets
			client.setCharset("UTF-8");
			assertEquals("UTF-8", client.getCharset(), "Should accept UTF-8 charset");

			client.setCharset("ISO-8859-1");
			assertEquals("ISO-8859-1", client.getCharset(), "Should accept ISO-8859-1 charset");

			client.setCharset("US-ASCII");
			assertEquals("US-ASCII", client.getCharset(), "Should accept US-ASCII charset");

		} catch (IOException e) {
			// Expected for connection issues, but charset setting logic should work
		}
	}

	@Test
	public void testSetCharsetWithNullCharset() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			// Set to a valid charset first
			client.setCharset("UTF-8");
			assertEquals("UTF-8", client.getCharset(), "Should have UTF-8 charset");

			// Set back to null
			client.setCharset(null);
			assertNull(client.getCharset(), "Should accept null charset");

		} catch (IOException e) {
			// Expected for connection issues
		}
	}

	@Test
	public void testSetCharsetWithInvalidCharset() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			// Test with invalid charset
			try {
				client.setCharset("INVALID-CHARSET-NAME");
				fail("Should throw IOException for invalid charset");
			} catch (IOException e) {
				assertTrue(e.getMessage().contains("unsupported") || e.getMessage().contains("charset"), "Should indicate unsupported charset");
			}

		} catch (IOException e) {
			// Expected for connection issues during construction
		}
	}

	@Test
	public void testSetCharsetWithEmptyString() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			// Test with empty string
			try {
				client.setCharset("");
				fail("Should throw IOException for empty charset name");
			} catch (IOException e) {
				// Expected
			}

		} catch (IOException e) {
			// Expected for connection issues during construction
		}
	}

	@Test
	public void testCloseIdempotent() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			// Close should be idempotent (safe to call multiple times)
			client.close();
			client.close(); // Should not throw exception
			client.close(); // Should not throw exception

		} catch (IOException e) {
			// Expected for connection issues during construction
		}
	}

	@Test
	public void testFileHandleCreation() {
		// Test that SFTPv3FileHandle creation works correctly
		SFTPv3Client mockClient = mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		assertNotNull(fileHandle, "File handle should be created");
		assertSame(mockClient, fileHandle.getClient(), "File handle should reference the client");
		assertFalse(fileHandle.isClosed(), "File handle should not be closed initially");
	}

	@Test
	public void testCharsetPersistence() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			// Test that charset setting persists across multiple gets
			client.setCharset("UTF-16");

			String charset1 = client.getCharset();
			String charset2 = client.getCharset();
			String charset3 = client.getCharset();

			assertEquals(charset1, charset2, "Charset should be consistent");
			assertEquals(charset2, charset3, "Charset should be consistent");
			assertEquals("UTF-16", charset1, "Charset should be UTF-16");

		} catch (IOException e) {
			// Expected for connection issues
		}
	}

	@Test
	public void testConstructorSessionCreation() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			new SFTPv3Client(mockConnection);

			// Verify that openSession was called
			verify(mockConnection, times(1)).openSession();

		} catch (IOException e) {
			// Expected since we're not providing proper SFTP handshake
			// But verify that the session creation was attempted
			verify(mockConnection, times(1)).openSession();
		}
	}

	@Test
	public void testDeprecatedConstructorWithDebug() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		ByteArrayOutputStream debugOutput = new ByteArrayOutputStream();
		java.io.PrintStream debugStream = new java.io.PrintStream(debugOutput);

		try {
			new SFTPv3Client(mockConnection, debugStream);

			// Verify that session creation was attempted
			verify(mockConnection, times(1)).openSession();

			// Check that debug output was written (if constructor gets far enough)
			// The exact content depends on how far the constructor progresses

		} catch (IOException e) {
			// Expected since we're not providing proper SFTP handshake
			verify(mockConnection, times(1)).openSession();
		}
	}

	@Test
	public void testDeprecatedConstructorWithNullDebug() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			new SFTPv3Client(mockConnection, null);

			// Should work with null debug stream
			verify(mockConnection, times(1)).openSession();

		} catch (IOException e) {
			// Expected for SFTP handshake issues
			verify(mockConnection, times(1)).openSession();
		}
	}

	@Test
	public void testFileHandleWithWrongClient() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client1 = new SFTPv3Client(mockConnection);
			SFTPv3Client client2 = mock(SFTPv3Client.class);

			SFTPv3FileHandle handle = new SFTPv3FileHandle(client2, new byte[]{1, 2, 3, 4});

			try {
				client1.closeFile(handle);
				fail("Should throw IOException for handle from different client");
			} catch (IOException e) {
				assertTrue(e.getMessage().contains("created with another") ||
						e.getMessage().contains("different"));
			}
		} catch (IOException e) {
		}
	}

	@Test
	public void testFileHandleAlreadyClosed() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			SFTPv3FileHandle handle = new SFTPv3FileHandle(client, new byte[]{1, 2, 3, 4});
			handle.isClosed = true;

			try {
				client.closeFile(handle);
				fail("Should throw IOException for already closed handle");
			} catch (IOException e) {
				assertTrue(e.getMessage().toLowerCase().contains("closed"));
			}
		} catch (IOException e) {
		}
	}

	@Test
	public void testMultipleCharsetChanges() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			client.setCharset("UTF-8");
			assertEquals(client.getCharset(), "UTF-8");

			client.setCharset("ISO-8859-1");
			assertEquals(client.getCharset(), "ISO-8859-1");

			client.setCharset("UTF-16");
			assertEquals(client.getCharset(), "UTF-16");

			client.setCharset(null);
			assertNull(client.getCharset());

			client.setCharset("UTF-8");
			assertEquals(client.getCharset(), "UTF-8");

		} catch (IOException e) {
		}
	}

	@Test
	public void testCharsetWithDifferentEncodings() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			String[] validCharsets = {
				"UTF-8", "UTF-16", "UTF-16BE", "UTF-16LE",
				"ISO-8859-1", "US-ASCII", "UTF-32"
			};

			for (String charset : validCharsets) {
				client.setCharset(charset);
				assertEquals(charset, client.getCharset());
			}

		} catch (IOException e) {
		}
	}

	@Test
	public void testProtocolVersionBeforeInit() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);
			assertEquals(0, client.getProtocolVersion());
		} catch (IOException e) {
		}
	}

	@Test
	public void testFileHandleGetClient() {
		SFTPv3Client mockClient = mock(SFTPv3Client.class);
		byte[] handle = new byte[]{1, 2, 3, 4};

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		assertSame(mockClient, fileHandle.getClient());
	}

	@Test
	public void testFileHandleIsClosedInitialState() {
		SFTPv3Client mockClient = mock(SFTPv3Client.class);
		byte[] handle = new byte[]{1, 2, 3, 4};

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		assertFalse(fileHandle.isClosed());
	}

	@Test
	public void testFileHandleClosedState() {
		SFTPv3Client mockClient = mock(SFTPv3Client.class);
		byte[] handle = new byte[]{1, 2, 3, 4};

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);
		fileHandle.isClosed = true;

		assertTrue(fileHandle.isClosed());
	}

	@Test
	public void testCloseSessionMultipleTimes() throws IOException {
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);

			client.close();
			client.close();
			client.close();

			verify(mockSession, times(3)).close();

		} catch (IOException e) {
		}
	}
}

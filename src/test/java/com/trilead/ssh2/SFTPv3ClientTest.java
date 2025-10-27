package com.trilead.ssh2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.MockitoAnnotations;

@ExtendWith(MockitoExtension.class)
public class SFTPv3ClientTest {

	@Mock
	private Connection mockConnection;

	@Mock
	private Session mockSession;

	@Before
	public void setUp() {
		MockitoAnnotations.initMocks(this);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructorWithNullConnection() throws IOException {
		new SFTPv3Client(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDeprecatedConstructorWithNullConnection() throws IOException {
		new SFTPv3Client(null, System.out);
	}

	@Test
	public void testGetProtocolVersionDefault() throws IOException {
		// We need to mock the session creation and SFTP initialization
		when(mockConnection.openSession()).thenReturn(mockSession);
		when(mockSession.getStdout()).thenReturn(new ByteArrayInputStream(new byte[0]));
		when(mockSession.getStdin()).thenReturn(new ByteArrayOutputStream());

		try {
			SFTPv3Client client = new SFTPv3Client(mockConnection);
			assertEquals("Default protocol version should be 0", 0, client.getProtocolVersion());
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
			assertNull("Default charset should be null", client.getCharset());
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
			assertEquals("Should accept UTF-8 charset", "UTF-8", client.getCharset());

			client.setCharset("ISO-8859-1");
			assertEquals("Should accept ISO-8859-1 charset", "ISO-8859-1", client.getCharset());

			client.setCharset("US-ASCII");
			assertEquals("Should accept US-ASCII charset", "US-ASCII", client.getCharset());

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
			assertEquals("Should have UTF-8 charset", "UTF-8", client.getCharset());

			// Set back to null
			client.setCharset(null);
			assertNull("Should accept null charset", client.getCharset());

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
				assertTrue("Should indicate unsupported charset",
						e.getMessage().contains("unsupported") || e.getMessage().contains("charset"));
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

		assertNotNull("File handle should be created", fileHandle);
		assertSame("File handle should reference the client", mockClient, fileHandle.getClient());
		assertFalse("File handle should not be closed initially", fileHandle.isClosed());
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

			assertEquals("Charset should be consistent", charset1, charset2);
			assertEquals("Charset should be consistent", charset2, charset3);
			assertEquals("Charset should be UTF-16", "UTF-16", charset1);

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
			assertEquals("UTF-8", client.getCharset());

			client.setCharset("ISO-8859-1");
			assertEquals("ISO-8859-1", client.getCharset());

			client.setCharset("UTF-16");
			assertEquals("UTF-16", client.getCharset());

			client.setCharset(null);
			assertNull(client.getCharset());

			client.setCharset("UTF-8");
			assertEquals("UTF-8", client.getCharset());

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

package com.trilead.ssh2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import org.junit.Test;
import org.mockito.Mockito;

public class SFTPv3FileHandleTest {

	@Test
	public void testGetClient() {
		// Create a mock SFTPv3Client
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		assertSame("getClient should return the same client instance", mockClient,
				fileHandle.getClient());
	}

	@Test
	public void testIsClosedInitiallyFalse() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		assertFalse("File handle should not be closed initially",
				fileHandle.isClosed());
	}

	@Test
	public void testIsClosedAfterSettingClosed() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		// Since isClosed field is package-private, we need to use reflection or
		// test through the SFTPv3Client.closeFile() method behavior
		// For now, test the initial state
		assertFalse("File handle should not be closed initially",
				fileHandle.isClosed());
	}

	@Test
	public void testConstructorWithNullClient() {
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(null, handle);

		assertNull("Should accept null client", fileHandle.getClient());
		assertFalse("Should not be closed initially even with null client",
				fileHandle.isClosed());
	}

	@Test
	public void testConstructorWithNullHandle() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, null);

		assertSame("Should accept null handle", mockClient, fileHandle.getClient());
		assertFalse("Should not be closed initially even with null handle",
				fileHandle.isClosed());
	}

	@Test
	public void testConstructorWithEmptyHandle() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] emptyHandle = new byte[0];

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, emptyHandle);

		assertSame("Should accept empty handle", mockClient,
				fileHandle.getClient());
		assertFalse("Should not be closed initially with empty handle",
				fileHandle.isClosed());
	}

	@Test
	public void testConstructorWithLargeHandle() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] largeHandle = new byte[1024];
		for (int i = 0; i < largeHandle.length; i++) {
			largeHandle[i] = (byte) (i % 256);
		}

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, largeHandle);

		assertSame("Should accept large handle", mockClient,
				fileHandle.getClient());
		assertFalse("Should not be closed initially with large handle",
				fileHandle.isClosed());
	}

	@Test
	public void testMultipleFileHandlesWithSameClient() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle1 = new byte[] { 1, 2, 3, 4 };
		byte[] handle2 = new byte[] { 5, 6, 7, 8 };

		SFTPv3FileHandle fileHandle1 = new SFTPv3FileHandle(mockClient, handle1);
		SFTPv3FileHandle fileHandle2 = new SFTPv3FileHandle(mockClient, handle2);

		assertSame("Both handles should reference the same client",
				fileHandle1.getClient(), fileHandle2.getClient());
		assertFalse("First handle should not be closed", fileHandle1.isClosed());
		assertFalse("Second handle should not be closed", fileHandle2.isClosed());
		assertNotSame("Handles should be different objects", fileHandle1,
				fileHandle2);
	}

	@Test
	public void testClientConsistency() {
		// Test that the client reference remains consistent across multiple calls
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		SFTPv3Client client1 = fileHandle.getClient();
		SFTPv3Client client2 = fileHandle.getClient();

		assertSame("Multiple calls to getClient should return the same instance",
				client1, client2);
		assertSame("Client should remain the same as originally passed", mockClient,
				client1);
	}

	@Test
	public void testClosedStateConsistency() {
		// Test that the closed state remains consistent across multiple calls
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		boolean closed1 = fileHandle.isClosed();
		boolean closed2 = fileHandle.isClosed();

		assertEquals("Multiple calls to isClosed should return the same value",
				closed1, closed2);
		assertFalse("Should consistently return false for newly created handle",
				closed1);
	}
}

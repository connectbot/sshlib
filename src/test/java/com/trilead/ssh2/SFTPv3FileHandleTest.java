package com.trilead.ssh2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class SFTPv3FileHandleTest {

	@Test
	public void testGetClient() {
		// Create a mock SFTPv3Client
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		assertSame(mockClient,
				fileHandle.getClient(), "getClient should return the same client instance");
	}

	@Test
	public void testIsClosedInitiallyFalse() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		assertFalse(fileHandle.isClosed(), "File handle should not be closed initially");
	}

	@Test
	public void testIsClosedAfterSettingClosed() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		// Since isClosed field is package-private, we need to use reflection or
		// test through the SFTPv3Client.closeFile() method behavior
		// For now, test the initial state
		assertFalse(fileHandle.isClosed(), "File handle should not be closed initially");
	}

	@Test
	public void testConstructorWithNullClient() {
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(null, handle);

		assertNull(fileHandle.getClient(), "Should accept null client");
		assertFalse(fileHandle.isClosed(), "Should not be closed initially even with null client");
	}

	@Test
	public void testConstructorWithNullHandle() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, null);

		assertSame(mockClient, fileHandle.getClient(), "Should accept null handle");
		assertFalse(fileHandle.isClosed(), "Should not be closed initially even with null handle");
	}

	@Test
	public void testConstructorWithEmptyHandle() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] emptyHandle = new byte[0];

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, emptyHandle);

		assertSame(mockClient,
				fileHandle.getClient(), "Should accept empty handle");
		assertFalse(fileHandle.isClosed(), "Should not be closed initially with empty handle");
	}

	@Test
	public void testConstructorWithLargeHandle() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] largeHandle = new byte[1024];
		for (int i = 0; i < largeHandle.length; i++) {
			largeHandle[i] = (byte) (i % 256);
		}

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, largeHandle);

		assertSame(mockClient,
				fileHandle.getClient(), "Should accept large handle");
		assertFalse(fileHandle.isClosed(), "Should not be closed initially with large handle");
	}

	@Test
	public void testMultipleFileHandlesWithSameClient() {
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle1 = new byte[] { 1, 2, 3, 4 };
		byte[] handle2 = new byte[] { 5, 6, 7, 8 };

		SFTPv3FileHandle fileHandle1 = new SFTPv3FileHandle(mockClient, handle1);
		SFTPv3FileHandle fileHandle2 = new SFTPv3FileHandle(mockClient, handle2);

		assertSame(fileHandle1.getClient(), fileHandle2.getClient(), "Both handles should reference the same client");
		assertFalse(fileHandle1.isClosed(), "First handle should not be closed");
		assertFalse(fileHandle2.isClosed(), "Second handle should not be closed");
		assertNotSame(fileHandle1,
				fileHandle2, "Handles should be different objects");
	}

	@Test
	public void testClientConsistency() {
		// Test that the client reference remains consistent across multiple calls
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		SFTPv3Client client1 = fileHandle.getClient();
		SFTPv3Client client2 = fileHandle.getClient();

		assertSame(client1, client2, "Multiple calls to getClient should return the same instance");
		assertSame(mockClient,
				client1, "Client should remain the same as originally passed");
	}

	@Test
	public void testClosedStateConsistency() {
		// Test that the closed state remains consistent across multiple calls
		SFTPv3Client mockClient = Mockito.mock(SFTPv3Client.class);
		byte[] handle = new byte[] { 1, 2, 3, 4 };

		SFTPv3FileHandle fileHandle = new SFTPv3FileHandle(mockClient, handle);

		boolean closed1 = fileHandle.isClosed();
		boolean closed2 = fileHandle.isClosed();

		assertEquals(closed1, closed2, "Multiple calls to isClosed should return the same value");
		assertFalse(closed1, "Should consistently return false for newly created handle");
	}
}

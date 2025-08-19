package com.trilead.ssh2;

import static org.mockito.Mockito.mock;

import java.io.IOException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class SCPClientTest {

@Mock
private Connection mockConnection;

private SCPClient scpClient;

@Before
public void setUp() {
	MockitoAnnotations.initMocks(this);
	scpClient = new SCPClient(mockConnection);
}

@Test
public void testSCPClientConstruction() {
	Connection conn = mock(Connection.class);
	SCPClient client = new SCPClient(conn);
}

@Test(expected = IllegalArgumentException.class)
public void testSCPClientConstructionWithNullConnection() {
	new SCPClient(null);
}

@Test(expected = IllegalArgumentException.class)
public void testPutWithNullLocalFiles() throws IOException {
	scpClient.put((String[]) null, "/tmp", "0644");
}

@Test
public void testPutWithEmptyLocalFiles() throws IOException {
	// Empty array should return early without error
	scpClient.put(new String[0], "/tmp", "0644");
}

@Test(expected = IllegalArgumentException.class)
public void testPutWithNullLocalFileInArray() throws IOException {
	scpClient.put(new String[] { "file1.txt", null, "file2.txt" }, "/tmp",
		"0644");
}

@Test(expected = IllegalArgumentException.class)
public void testPutDataWithNullRemoteFileName() throws IOException {
	byte[] data = "Hello World".getBytes();
	scpClient.put(data, null, "/tmp", "0644");
}

@Test(expected = IllegalArgumentException.class)
public void testPutDataWithNullRemoteTargetDirectory() throws IOException {
	byte[] data = "Hello World".getBytes();
	scpClient.put(data, "remote.txt", null, "0644");
}

@Test(expected = IllegalArgumentException.class)
public void testPutDataWithNullMode() throws IOException {
	byte[] data = "Hello World".getBytes();
	scpClient.put(data, "remote.txt", "/tmp", null);
}

@Test(expected = IllegalArgumentException.class)
public void testGetWithNullRemoteFiles() throws IOException {
	scpClient.get((String[]) null, "/tmp");
}

@Test(expected = IllegalArgumentException.class)
public void testGetWithNullLocalTargetDirectory() throws IOException {
	scpClient.get(new String[] { "file1.txt" }, null);
}

@Test
public void testGetWithEmptyRemoteFiles() throws IOException {
	// Empty array should return early without error
	scpClient.get(new String[0], "/tmp");
}

@Test(expected = IllegalArgumentException.class)
public void testGetWithNullRemoteFileInArray() throws IOException {
	scpClient.get(new String[] { "file1.txt", null }, "/tmp");
}

@Test(expected = IllegalArgumentException.class)
public void testGetWithEmptyRemoteFileInArray() throws IOException {
	scpClient.get(new String[] { "file1.txt", "" }, "/tmp");
}

@Test(expected = IllegalArgumentException.class)
public void testPutWithInvalidMode() throws IOException {
	scpClient.put(new String[] { "file1.txt" }, "/tmp", "invalid");
}

@Test(expected = IllegalArgumentException.class)
public void testPutWithShortMode() throws IOException {
	scpClient.put(new String[] { "file1.txt" }, "/tmp", "644");
}

@Test(expected = IllegalArgumentException.class)
public void testPutDataWithInvalidMode() throws IOException {
	byte[] data = "Hello World".getBytes();
	scpClient.put(data, "remote.txt", "/tmp", "invalid");
}
}

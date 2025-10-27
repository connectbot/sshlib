package com.trilead.ssh2;

import static org.mockito.Mockito.mock;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class SCPClientTest {

@Mock
private Connection mockConnection;

private SCPClient scpClient;

@BeforeEach
public void setUp() {
	scpClient = new SCPClient(mockConnection);
}

@Test
public void testSCPClientConstruction() {
	Connection conn = mock(Connection.class);
	SCPClient client = new SCPClient(conn);
}

@Test
	public void testSCPClientConstructionWithNullConnection() {
		assertThrows(IllegalArgumentException.class, () -> {
	new SCPClient(null);
		});
}

@Test
	public void testPutWithNullLocalFiles() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	scpClient.put((String[]) null, "/tmp", "0644");
		});
}

@Test
public void testPutWithEmptyLocalFiles() throws IOException {
	// Empty array should return early without error
	scpClient.put(new String[0], "/tmp", "0644");
}

@Test
	public void testPutWithNullLocalFileInArray() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	scpClient.put(new String[] { "file1.txt", null, "file2.txt" }, "/tmp",
		"0644");
		});
}

@Test
	public void testPutDataWithNullRemoteFileName() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	byte[] data = "Hello World".getBytes();
	scpClient.put(data, null, "/tmp", "0644");
		});
}

@Test
	public void testPutDataWithNullRemoteTargetDirectory() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	byte[] data = "Hello World".getBytes();
	scpClient.put(data, "remote.txt", null, "0644");
		});
}

@Test
	public void testPutDataWithNullMode() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	byte[] data = "Hello World".getBytes();
	scpClient.put(data, "remote.txt", "/tmp", null);
		});
}

@Test
	public void testGetWithNullRemoteFiles() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	scpClient.get((String[]) null, "/tmp");
		});
}

@Test
	public void testGetWithNullLocalTargetDirectory() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	scpClient.get(new String[] { "file1.txt" }, null);
		});
}

@Test
public void testGetWithEmptyRemoteFiles() throws IOException {
	// Empty array should return early without error
	scpClient.get(new String[0], "/tmp");
}

@Test
	public void testGetWithNullRemoteFileInArray() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	scpClient.get(new String[] { "file1.txt", null }, "/tmp");
		});
}

@Test
	public void testGetWithEmptyRemoteFileInArray() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	scpClient.get(new String[] { "file1.txt", "" }, "/tmp");
		});
}

@Test
	public void testPutWithInvalidMode() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	scpClient.put(new String[] { "file1.txt" }, "/tmp", "invalid");
		});
}

@Test
	public void testPutWithShortMode() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	scpClient.put(new String[] { "file1.txt" }, "/tmp", "644");
		});
}

@Test
	public void testPutDataWithInvalidMode() throws IOException {
		assertThrows(IllegalArgumentException.class, () -> {
	byte[] data = "Hello World".getBytes();
	scpClient.put(data, "remote.txt", "/tmp", "invalid");
		});
}
}

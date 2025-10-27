package com.trilead.ssh2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class SFTPv3FileAttributesTest {
@Test
public void testIsDirectoryWithNullPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = null;

	assertFalse(attributes.isDirectory(), "Should return false when permissions are null");
}

@Test
public void testIsDirectoryWithDirectoryPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0040755; // S_IFDIR | 0755

	assertTrue(attributes.isDirectory(), "Should return true for directory permissions");
}

@Test
public void testIsDirectoryWithRegularFilePermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100644; // S_IFREG | 0644

	assertFalse(attributes.isDirectory(), "Should return false for regular file permissions");
}

@Test
public void testIsRegularFileWithNullPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = null;

	assertFalse(attributes.isRegularFile(), "Should return false when permissions are null");
}

@Test
public void testIsRegularFileWithRegularFilePermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100644; // S_IFREG | 0644

	assertTrue(attributes.isRegularFile(), "Should return true for regular file permissions");
}

@Test
public void testIsRegularFileWithDirectoryPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0040755; // S_IFDIR | 0755

	assertFalse(attributes.isRegularFile(), "Should return false for directory permissions");
}

@Test
public void testIsSymlinkWithNullPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = null;

	assertFalse(attributes.isSymlink(), "Should return false when permissions are null");
}

@Test
public void testIsSymlinkWithSymlinkPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0120777; // S_IFLNK | 0777

	assertTrue(attributes.isSymlink(), "Should return true for symlink permissions");
}

@Test
public void testIsSymlinkWithRegularFilePermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100644; // S_IFREG | 0644

	assertFalse(attributes.isSymlink(), "Should return false for regular file permissions");
}

@Test
public void testGetOctalPermissionsWithNullPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = null;

	assertNull(attributes.getOctalPermissions(), "Should return null when permissions are null");
}

@Test
public void testGetOctalPermissionsWithStandardPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100644; // S_IFREG | 0644

	String octal = attributes.getOctalPermissions();
	assertEquals("0100644", octal, "Should return 7-digit octal string");
}

@Test
public void testGetOctalPermissionsWithDirectoryPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0040755; // S_IFDIR | 0755

	String octal = attributes.getOctalPermissions();
	assertEquals("0040755", octal, "Should return correct octal for directory");
}

@Test
public void testGetOctalPermissionsWithSymlinkPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0120777; // S_IFLNK | 0777

	String octal = attributes.getOctalPermissions();
	assertEquals("0120777", octal, "Should return correct octal for symlink");
}

@Test
public void testGetOctalPermissionsWithSpecialBits() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions =
		0107755; // S_IFREG | S_ISUID | S_ISGID | S_ISVTX | 0755

	String octal = attributes.getOctalPermissions();
	assertEquals("0107755",
				octal, "Should return correct octal with special bits");
}

@Test
public void testGetOctalPermissionsWithMinimalPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100000; // S_IFREG only, no permissions

	String octal = attributes.getOctalPermissions();
	assertEquals("0100000",
				octal, "Should return correct octal with leading zeros");
}

@Test
public void testGetOctalPermissionsWithSmallValue() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0000007; // Very small value

	String octal = attributes.getOctalPermissions();
	assertEquals("0000007", octal, "Should pad with leading zeros");
}

@Test
public void testGetOctalPermissionsWithMasking() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	// Set a value with bits outside the 0177777 mask
	attributes.permissions = 0xFFFFFFFF; // All bits set

	String octal = attributes.getOctalPermissions();
	// Should be masked with 0177777 = 0177777 in octal
	assertEquals("0177777", octal, "Should mask permissions correctly");
}

@Test
public void testAllFileTypesDetection() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();

	// Test various file types
	int[] fileTypes = {
		0100000, // S_IFREG - regular file
		0040000, // S_IFDIR - directory
		0120000, // S_IFLNK - symbolic link
		0020000, // S_IFCHR - character device
		0060000, // S_IFBLK - block device
		0010000, // S_IFIFO - FIFO
		0140000  // S_IFSOCK - socket
	};

	for (int i = 0; i < fileTypes.length; i++) {
	attributes.permissions = fileTypes[i] | 0644;

	boolean isRegular = attributes.isRegularFile();
	boolean isDirectory = attributes.isDirectory();
	boolean isSymlink = attributes.isSymlink();

	// Verify that only the correct file type is detected

	if (i == 0) { // regular file
		assertTrue(isRegular, "Regular file should be detected as regular file");
		assertFalse(isDirectory, "Regular file should not be detected as directory");
		assertFalse(isSymlink, "Regular file should not be detected as symlink");
	} else if (i == 1) { // directory
		assertFalse(isRegular, "Directory should not be detected as regular file");
		assertTrue(isDirectory, "Directory should be detected as directory");
		assertFalse(isSymlink, "Directory should not be detected as symlink");
	} else if (i == 2) { // symlink
		assertFalse(isRegular, "Symlink should not be detected as regular file");
		assertFalse(isDirectory, "Symlink should not be detected as directory");
		assertTrue(isSymlink, "Symlink should be detected as symlink");
	} else if (i == 3) { // char device
		assertFalse(isRegular, "Char device should not be detected as regular file");
		assertFalse(isDirectory, "Char device should not be detected as directory");
		assertFalse(isSymlink, "Char device should not be detected as symlink");
	} else if (i == 4) { // block device
		assertFalse(isRegular, "Block device should not be detected as regular file");
		assertFalse(isDirectory, "Block device should not be detected as directory");
		assertFalse(isSymlink, "Block device should not be detected as symlink");
	} else if (i == 5) { // FIFO
		assertFalse(isRegular, "FIFO should not be detected as regular file");
		assertFalse(isDirectory, "FIFO should not be detected as directory");
		assertFalse(isSymlink, "FIFO should not be detected as symlink");
	} else if (i == 6) { // socket
		assertFalse(isRegular, "Socket should not be detected as regular file");
		assertFalse(isDirectory, "Socket should not be detected as directory");
		assertFalse(isSymlink, "Socket should not be detected as symlink");
	}
	}
}

@Test
public void testOctalPermissionsLength() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();

	// Test various permission values to ensure 7-digit output
	int[] testValues = {0000000, 0000001, 0000010, 0000100, 0001000,
						0010000, 0100000, 0177777, 0040755, 0100644};

	for (int value : testValues) {
	attributes.permissions = value;
	String octal = attributes.getOctalPermissions();
	assertEquals(7, octal.length(),
				"Octal permissions should always be 7 digits for value " +
					Integer.toOctalString(value));
	}
}

@Test
public void testNegativePermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = -1; // All bits set

	// Should still work due to masking
	String octal = attributes.getOctalPermissions();
	assertNotNull(octal, "Should handle negative permissions");
	assertEquals(7, octal.length(), "Should be 7 digits");

	// The behavior should be consistent with masking
	assertEquals("0177777", octal, "Should mask negative value correctly");
}

@Test
public void testZeroPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0;

	assertFalse(attributes.isDirectory(), "Zero permissions should not be directory");
	assertFalse(attributes.isRegularFile(), "Zero permissions should not be regular file");
	assertFalse(attributes.isSymlink(), "Zero permissions should not be symlink");
	assertEquals("0000000",
				attributes.getOctalPermissions(), "Zero permissions should return 0000000");
}
}

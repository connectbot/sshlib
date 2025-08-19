package com.trilead.ssh2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class SFTPv3FileAttributesTest {
@Test
public void testIsDirectoryWithNullPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = null;

	assertFalse("Should return false when permissions are null",
				attributes.isDirectory());
}

@Test
public void testIsDirectoryWithDirectoryPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0040755; // S_IFDIR | 0755

	assertTrue("Should return true for directory permissions",
			attributes.isDirectory());
}

@Test
public void testIsDirectoryWithRegularFilePermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100644; // S_IFREG | 0644

	assertFalse("Should return false for regular file permissions",
				attributes.isDirectory());
}

@Test
public void testIsRegularFileWithNullPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = null;

	assertFalse("Should return false when permissions are null",
				attributes.isRegularFile());
}

@Test
public void testIsRegularFileWithRegularFilePermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100644; // S_IFREG | 0644

	assertTrue("Should return true for regular file permissions",
			attributes.isRegularFile());
}

@Test
public void testIsRegularFileWithDirectoryPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0040755; // S_IFDIR | 0755

	assertFalse("Should return false for directory permissions",
				attributes.isRegularFile());
}

@Test
public void testIsSymlinkWithNullPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = null;

	assertFalse("Should return false when permissions are null",
				attributes.isSymlink());
}

@Test
public void testIsSymlinkWithSymlinkPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0120777; // S_IFLNK | 0777

	assertTrue("Should return true for symlink permissions",
			attributes.isSymlink());
}

@Test
public void testIsSymlinkWithRegularFilePermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100644; // S_IFREG | 0644

	assertFalse("Should return false for regular file permissions",
				attributes.isSymlink());
}

@Test
public void testGetOctalPermissionsWithNullPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = null;

	assertNull("Should return null when permissions are null",
			attributes.getOctalPermissions());
}

@Test
public void testGetOctalPermissionsWithStandardPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100644; // S_IFREG | 0644

	String octal = attributes.getOctalPermissions();
	assertEquals("Should return 7-digit octal string", "0100644", octal);
}

@Test
public void testGetOctalPermissionsWithDirectoryPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0040755; // S_IFDIR | 0755

	String octal = attributes.getOctalPermissions();
	assertEquals("Should return correct octal for directory", "0040755", octal);
}

@Test
public void testGetOctalPermissionsWithSymlinkPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0120777; // S_IFLNK | 0777

	String octal = attributes.getOctalPermissions();
	assertEquals("Should return correct octal for symlink", "0120777", octal);
}

@Test
public void testGetOctalPermissionsWithSpecialBits() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions =
		0107755; // S_IFREG | S_ISUID | S_ISGID | S_ISVTX | 0755

	String octal = attributes.getOctalPermissions();
	assertEquals("Should return correct octal with special bits", "0107755",
				octal);
}

@Test
public void testGetOctalPermissionsWithMinimalPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0100000; // S_IFREG only, no permissions

	String octal = attributes.getOctalPermissions();
	assertEquals("Should return correct octal with leading zeros", "0100000",
				octal);
}

@Test
public void testGetOctalPermissionsWithSmallValue() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0000007; // Very small value

	String octal = attributes.getOctalPermissions();
	assertEquals("Should pad with leading zeros", "0000007", octal);
}

@Test
public void testGetOctalPermissionsWithMasking() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	// Set a value with bits outside the 0177777 mask
	attributes.permissions = 0xFFFFFFFF; // All bits set

	String octal = attributes.getOctalPermissions();
	// Should be masked with 0177777 = 0177777 in octal
	assertEquals("Should mask permissions correctly", "0177777", octal);
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
		assertTrue("Regular file should be detected as regular file",
				isRegular);
		assertFalse("Regular file should not be detected as directory",
					isDirectory);
		assertFalse("Regular file should not be detected as symlink",
					isSymlink);
	} else if (i == 1) { // directory
		assertFalse("Directory should not be detected as regular file",
					isRegular);
		assertTrue("Directory should be detected as directory", isDirectory);
		assertFalse("Directory should not be detected as symlink", isSymlink);
	} else if (i == 2) { // symlink
		assertFalse("Symlink should not be detected as regular file",
					isRegular);
		assertFalse("Symlink should not be detected as directory", isDirectory);
		assertTrue("Symlink should be detected as symlink", isSymlink);
	} else if (i == 3) { // char device
		assertFalse("Char device should not be detected as regular file",
					isRegular);
		assertFalse("Char device should not be detected as directory",
					isDirectory);
		assertFalse("Char device should not be detected as symlink", isSymlink);
	} else if (i == 4) { // block device
		assertFalse("Block device should not be detected as regular file",
					isRegular);
		assertFalse("Block device should not be detected as directory",
					isDirectory);
		assertFalse("Block device should not be detected as symlink",
					isSymlink);
	} else if (i == 5) { // FIFO
		assertFalse("FIFO should not be detected as regular file", isRegular);
		assertFalse("FIFO should not be detected as directory", isDirectory);
		assertFalse("FIFO should not be detected as symlink", isSymlink);
	} else if (i == 6) { // socket
		assertFalse("Socket should not be detected as regular file", isRegular);
		assertFalse("Socket should not be detected as directory", isDirectory);
		assertFalse("Socket should not be detected as symlink", isSymlink);
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
	assertEquals("Octal permissions should always be 7 digits for value " +
					Integer.toOctalString(value),
				7, octal.length());
	}
}

@Test
public void testNegativePermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = -1; // All bits set

	// Should still work due to masking
	String octal = attributes.getOctalPermissions();
	assertNotNull("Should handle negative permissions", octal);
	assertEquals("Should be 7 digits", 7, octal.length());

	// The behavior should be consistent with masking
	assertEquals("Should mask negative value correctly", "0177777", octal);
}

@Test
public void testZeroPermissions() {
	SFTPv3FileAttributes attributes = new SFTPv3FileAttributes();
	attributes.permissions = 0;

	assertFalse("Zero permissions should not be directory",
				attributes.isDirectory());
	assertFalse("Zero permissions should not be regular file",
				attributes.isRegularFile());
	assertFalse("Zero permissions should not be symlink",
				attributes.isSymlink());
	assertEquals("Zero permissions should return 0000000", "0000000",
				attributes.getOctalPermissions());
}
}

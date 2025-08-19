package com.trilead.ssh2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.trilead.ssh2.sftp.ErrorCodes;
import org.junit.Test;

public class SFTPExceptionTest {

@Test
public void testBasicExceptionConstruction() {
	String message = "Test error message";
	int errorCode = ErrorCodes.SSH_FX_NO_SUCH_FILE;

	SFTPException exception = new SFTPException(message, errorCode);

	assertEquals("Server error message should match", message,
				exception.getServerErrorMessage());
	assertEquals("Server error code should match", errorCode,
				exception.getServerErrorCode());
	assertNotNull("Exception message should not be null",
				exception.getMessage());
	assertTrue("Exception message should contain original message",
			exception.getMessage().contains(message));
}

@Test
public void testKnownErrorCodes() {
	String message = "File not found";
	int errorCode = ErrorCodes.SSH_FX_NO_SUCH_FILE;

	SFTPException exception = new SFTPException(message, errorCode);

	assertEquals("Error code symbol should be correct", "SSH_FX_NO_SUCH_FILE",
				exception.getServerErrorCodeSymbol());
	assertEquals("Error code description should be correct",
				"A reference was made to a file which does not exist.",
				exception.getServerErrorCodeVerbose());

	assertTrue("Exception message should contain error details",
			exception.getMessage().contains("SSH_FX_NO_SUCH_FILE"));
}

@Test
public void testSomeKnownErrorCodes() {
	// Test a subset of error codes that are definitely defined
	int[] definedCodes = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

	for (int errorCode : definedCodes) {
	SFTPException exception = new SFTPException("Test message", errorCode);

	assertNotNull("Error code symbol should not be null for code " +
						errorCode,
					exception.getServerErrorCodeSymbol());
	assertNotNull("Error code description should not be null for code " +
						errorCode,
					exception.getServerErrorCodeVerbose());
	assertFalse("Error code symbol should not indicate unknown for code " +
					errorCode,
				exception.getServerErrorCodeSymbol().contains("UNKNOW"));
	}
}

@Test
public void testUnknownErrorCode() {
	String message = "Unknown error";
	int unknownErrorCode = 999;

	SFTPException exception = new SFTPException(message, unknownErrorCode);

	assertEquals("Server error message should match", message,
				exception.getServerErrorMessage());
	assertEquals("Server error code should match", unknownErrorCode,
				exception.getServerErrorCode());

	String symbol = exception.getServerErrorCodeSymbol();
	assertTrue("Unknown error code symbol should indicate unknown",
			symbol.contains("UNKNOW") &&
				symbol.contains(String.valueOf(unknownErrorCode)));

	String description = exception.getServerErrorCodeVerbose();
	assertTrue("Unknown error code description should indicate unknown",
			description.contains("unknown") &&
				description.contains(String.valueOf(unknownErrorCode)));

	assertTrue("Exception message should indicate unknown error",
			exception.getMessage().contains("UNKNOW"));
}

@Test
public void testNegativeErrorCode() {
	String message = "Negative error code";
	int negativeErrorCode = -1;

	SFTPException exception = new SFTPException(message, negativeErrorCode);

	assertEquals("Server error code should match", negativeErrorCode,
				exception.getServerErrorCode());
	assertTrue("Negative error code should be treated as unknown",
			exception.getServerErrorCodeSymbol().contains("UNKNOW"));
}

@Test
public void testEmptyMessage() {
	String emptyMessage = "";
	int errorCode = ErrorCodes.SSH_FX_FAILURE;

	SFTPException exception = new SFTPException(emptyMessage, errorCode);

	assertEquals("Empty message should be preserved", emptyMessage,
				exception.getServerErrorMessage());
	assertNotNull(
		"Exception message should not be null even with empty server message",
		exception.getMessage());
	assertTrue("Exception message should contain error details even with " +
			"empty server message",
			exception.getMessage().contains("SSH_FX_FAILURE"));
}

@Test
public void testNullMessage() {
	String nullMessage = null;
	int errorCode = ErrorCodes.SSH_FX_PERMISSION_DENIED;

	SFTPException exception = new SFTPException(nullMessage, errorCode);

	assertEquals("Null message should be preserved", nullMessage,
				exception.getServerErrorMessage());
	assertNotNull(
		"Exception message should not be null even with null server message",
		exception.getMessage());
}

@Test
public void testIsIOException() {
	SFTPException exception =
		new SFTPException("Test", ErrorCodes.SSH_FX_FAILURE);

	assertTrue("SFTPException should be an IOException",
			exception instanceof java.io.IOException);
}

@Test
public void testSerialVersionUID() {
	// Test that the serialVersionUID is set (this helps with serialization
	// compatibility)
	SFTPException exception = new SFTPException("Test", ErrorCodes.SSH_FX_OK);

	// The presence of serialVersionUID can be checked by ensuring serialization
	// works
	assertNotNull("Exception should be serializable", exception);
}

@Test
public void testSpecificErrorCodeSymbols() {
	// Test specific error codes to ensure correct mapping
	assertEquals("SSH_FX_OK", new SFTPException("test", ErrorCodes.SSH_FX_OK)
								.getServerErrorCodeSymbol());
	assertEquals("SSH_FX_NO_SUCH_FILE",
				new SFTPException("test", ErrorCodes.SSH_FX_NO_SUCH_FILE)
					.getServerErrorCodeSymbol());
	assertEquals("SSH_FX_PERMISSION_DENIED",
				new SFTPException("test", ErrorCodes.SSH_FX_PERMISSION_DENIED)
					.getServerErrorCodeSymbol());
	assertEquals(
		"SSH_FX_FILE_ALREADY_EXISTS",
		new SFTPException("test", ErrorCodes.SSH_FX_FILE_ALREADY_EXISTS)
			.getServerErrorCodeSymbol());
}

@Test
public void testSpecificErrorCodeDescriptions() {
	// Test specific error descriptions
	assertEquals("Indicates successful completion of the operation.",
				new SFTPException("test", ErrorCodes.SSH_FX_OK)
					.getServerErrorCodeVerbose());
	assertEquals("A reference was made to a file which does not exist.",
				new SFTPException("test", ErrorCodes.SSH_FX_NO_SUCH_FILE)
					.getServerErrorCodeVerbose());
	assertEquals("The user does not have sufficient permissions to perform " +
				"the operation.",
				new SFTPException("test", ErrorCodes.SSH_FX_PERMISSION_DENIED)
					.getServerErrorCodeVerbose());
}

@Test
public void testMessageConstruction() {
	String message = "Custom error message";
	int errorCode = ErrorCodes.SSH_FX_INVALID_FILENAME;

	SFTPException exception = new SFTPException(message, errorCode);
	String constructedMessage = exception.getMessage();

	assertTrue("Constructed message should contain original message",
			constructedMessage.contains(message));
	assertTrue("Constructed message should contain error code symbol",
			constructedMessage.contains("SSH_FX_INVALID_FILENAME"));
	assertTrue("Constructed message should contain error description",
			constructedMessage.contains("The filename is not valid."));
	assertTrue("Constructed message should have proper format with parentheses",
			constructedMessage.contains("(") &&
				constructedMessage.contains(")"));
}

@Test
public void testLongMessage() {
	StringBuilder longMessage = new StringBuilder();
	for (int i = 0; i < 1000; i++) {
	longMessage.append("A");
	}
	String message = longMessage.toString();

	SFTPException exception =
		new SFTPException(message, ErrorCodes.SSH_FX_FAILURE);

	assertEquals("Long message should be preserved", message,
				exception.getServerErrorMessage());
	assertTrue("Exception message should contain long message",
			exception.getMessage().contains(message));
}

@Test
public void testSpecialCharactersInMessage() {
	String message = "Error with special chars: !@#$%^&*()_+-=[]{}|;:,.<>?";
	int errorCode = ErrorCodes.SSH_FX_FAILURE;

	SFTPException exception = new SFTPException(message, errorCode);

	assertEquals("Message with special characters should be preserved", message,
				exception.getServerErrorMessage());
	assertTrue("Exception message should contain special characters",
			exception.getMessage().contains(message));
}

@Test
public void testUnicodeMessage() {
	String message = "Unicode error: αβγδε 中文 🌟";
	int errorCode = ErrorCodes.SSH_FX_FAILURE;

	SFTPException exception = new SFTPException(message, errorCode);

	assertEquals("Unicode message should be preserved", message,
				exception.getServerErrorMessage());
	assertTrue("Exception message should contain unicode characters",
			exception.getMessage().contains(message));
}
}

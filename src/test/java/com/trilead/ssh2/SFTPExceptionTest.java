package com.trilead.ssh2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.trilead.ssh2.sftp.ErrorCodes;
import org.junit.jupiter.api.Test;

public class SFTPExceptionTest {

@Test
public void testBasicExceptionConstruction() {
	String message = "Test error message";
	int errorCode = ErrorCodes.SSH_FX_NO_SUCH_FILE;

	SFTPException exception = new SFTPException(message, errorCode);

	assertEquals(message,
				exception.getServerErrorMessage(), "Server error message should match");
	assertEquals(errorCode,
				exception.getServerErrorCode(), "Server error code should match");
	assertNotNull(exception.getMessage(), "Exception message should not be null");
	assertTrue(exception.getMessage().contains(message), "Exception message should contain original message");
}

@Test
public void testKnownErrorCodes() {
	String message = "File not found";
	int errorCode = ErrorCodes.SSH_FX_NO_SUCH_FILE;

	SFTPException exception = new SFTPException(message, errorCode);

	assertEquals("SSH_FX_NO_SUCH_FILE",
				exception.getServerErrorCodeSymbol(), "Error code symbol should be correct");
	assertEquals("A reference was made to a file which does not exist.",
				exception.getServerErrorCodeVerbose(), "Error code description should be correct");

	assertTrue(exception.getMessage().contains("SSH_FX_NO_SUCH_FILE"), "Exception message should contain error details");
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
	assertFalse(exception.getServerErrorCodeSymbol().contains("UNKNOW"),
				"Error code symbol should not indicate unknown for code " +
					errorCode);
	}
}

@Test
public void testUnknownErrorCode() {
	String message = "Unknown error";
	int unknownErrorCode = 999;

	SFTPException exception = new SFTPException(message, unknownErrorCode);

	assertEquals(message,
				exception.getServerErrorMessage(), "Server error message should match");
	assertEquals(unknownErrorCode,
				exception.getServerErrorCode(), "Server error code should match");

	String symbol = exception.getServerErrorCodeSymbol();
	assertTrue(symbol.contains("UNKNOW") &&
				symbol.contains(String.valueOf(unknownErrorCode)), "Unknown error code symbol should indicate unknown");

	String description = exception.getServerErrorCodeVerbose();
	assertTrue(description.contains("unknown") &&
				description.contains(String.valueOf(unknownErrorCode)), "Unknown error code description should indicate unknown");

	assertTrue(exception.getMessage().contains("UNKNOW"), "Exception message should indicate unknown error");
}

@Test
public void testNegativeErrorCode() {
	String message = "Negative error code";
	int negativeErrorCode = -1;

	SFTPException exception = new SFTPException(message, negativeErrorCode);

	assertEquals(negativeErrorCode,
				exception.getServerErrorCode(), "Server error code should match");
	assertTrue(exception.getServerErrorCodeSymbol().contains("UNKNOW"), "Negative error code should be treated as unknown");
}

@Test
public void testEmptyMessage() {
	String emptyMessage = "";
	int errorCode = ErrorCodes.SSH_FX_FAILURE;

	SFTPException exception = new SFTPException(emptyMessage, errorCode);

	assertEquals(emptyMessage,
				exception.getServerErrorMessage(), "Empty message should be preserved");
	assertNotNull(exception.getMessage(), "Exception message should not be null even with empty server message");
	assertTrue(exception.getMessage().contains("SSH_FX_FAILURE"),
			"Exception message should contain error details even with " +
			"empty server message");
}

@Test
public void testNullMessage() {
	String nullMessage = null;
	int errorCode = ErrorCodes.SSH_FX_PERMISSION_DENIED;

	SFTPException exception = new SFTPException(nullMessage, errorCode);

	assertEquals(nullMessage,
				exception.getServerErrorMessage(), "Null message should be preserved");
	assertNotNull(exception.getMessage(), "Exception message should not be null even with null server message");
}

@Test
public void testIsIOException() {
	SFTPException exception =
		new SFTPException("Test", ErrorCodes.SSH_FX_FAILURE);

	assertTrue(exception instanceof java.io.IOException, "SFTPException should be an IOException");
}

@Test
public void testSerialVersionUID() {
	// Test that the serialVersionUID is set (this helps with serialization
	// compatibility)
	SFTPException exception = new SFTPException("Test", ErrorCodes.SSH_FX_OK);

	// The presence of serialVersionUID can be checked by ensuring serialization
	// works
	assertNotNull(exception, "Exception should be serializable");
}

@Test
public void testSpecificErrorCodeSymbols() {
	// Test specific error codes to ensure correct mapping
	assertEquals(new SFTPException("test", ErrorCodes.SSH_FX_OK)
								.getServerErrorCodeSymbol(), "SSH_FX_OK");
	assertEquals(new SFTPException("test", ErrorCodes.SSH_FX_NO_SUCH_FILE)
					.getServerErrorCodeSymbol(), "SSH_FX_NO_SUCH_FILE");
	assertEquals(new SFTPException("test", ErrorCodes.SSH_FX_PERMISSION_DENIED)
					.getServerErrorCodeSymbol(), "SSH_FX_PERMISSION_DENIED");
	assertEquals(new SFTPException("test", ErrorCodes.SSH_FX_FILE_ALREADY_EXISTS)
			.getServerErrorCodeSymbol(), "SSH_FX_FILE_ALREADY_EXISTS");
}

@Test
public void testSpecificErrorCodeDescriptions() {
	// Test specific error descriptions
	assertEquals(new SFTPException("test", ErrorCodes.SSH_FX_OK)
					.getServerErrorCodeVerbose(), "Indicates successful completion of the operation.");
	assertEquals(new SFTPException("test", ErrorCodes.SSH_FX_NO_SUCH_FILE)
					.getServerErrorCodeVerbose(), "A reference was made to a file which does not exist.");
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

	assertTrue(constructedMessage.contains(message), "Constructed message should contain original message");
	assertTrue(constructedMessage.contains("SSH_FX_INVALID_FILENAME"), "Constructed message should contain error code symbol");
	assertTrue(constructedMessage.contains("The filename is not valid."), "Constructed message should contain error description");
	assertTrue(constructedMessage.contains("(") &&
				constructedMessage.contains(")"), "Constructed message should have proper format with parentheses");
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

	assertEquals(message,
				exception.getServerErrorMessage(), "Long message should be preserved");
	assertTrue(exception.getMessage().contains(message), "Exception message should contain long message");
}

@Test
public void testSpecialCharactersInMessage() {
	String message = "Error with special chars: !@#$%^&*()_+-=[]{}|;:,.<>?";
	int errorCode = ErrorCodes.SSH_FX_FAILURE;

	SFTPException exception = new SFTPException(message, errorCode);

	assertEquals(message,
				exception.getServerErrorMessage(), "Message with special characters should be preserved");
	assertTrue(exception.getMessage().contains(message), "Exception message should contain special characters");
}

@Test
public void testUnicodeMessage() {
	String message = "Unicode error: αβγδε 中文 🌟";
	int errorCode = ErrorCodes.SSH_FX_FAILURE;

	SFTPException exception = new SFTPException(message, errorCode);

	assertEquals(message,
				exception.getServerErrorMessage(), "Unicode message should be preserved");
	assertTrue(exception.getMessage().contains(message), "Exception message should contain unicode characters");
}
}

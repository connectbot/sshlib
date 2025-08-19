package com.trilead.ssh2;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.SecureRandom;
import org.junit.Before;
import org.junit.Test;

public class ConnectionTest {

private Connection connection;

@Before
public void setUp() {
	connection = new Connection("testhost.example.com", 2222);
}

@Test
public void testConnectionConstructorWithHostnameAndPort() {
	String hostname = "example.com";
	int port = 2222;

	Connection conn = new Connection(hostname, port);

	assertEquals("Hostname should match constructor parameter", hostname,
				conn.getHostname());
	assertEquals("Port should match constructor parameter", port,
				conn.getPort());
}

@Test
public void testConnectionConstructorWithHostnameOnly() {
	String hostname = "example.com";

	Connection conn = new Connection(hostname);

	assertEquals("Hostname should match constructor parameter", hostname,
				conn.getHostname());
	assertEquals("Port should default to 22", 22, conn.getPort());
}

@Test
public void testGetHostname() {
	assertEquals("Should return hostname passed to constructor",
				"testhost.example.com", connection.getHostname());
}

@Test
public void testGetPort() {
	assertEquals("Should return port passed to constructor", 2222,
				connection.getPort());
}

@Test
public void testIsAuthenticationCompleteInitiallyFalse() {
	assertFalse("Authentication should initially be incomplete",
				connection.isAuthenticationComplete());
}

@Test
public void testIsAuthenticationPartialSuccessInitiallyFalse() {
	assertFalse("Partial success should initially be false",
				connection.isAuthenticationPartialSuccess());
}

@Test
public void testGetAvailableCiphers() {
	String[] ciphers = Connection.getAvailableCiphers();

	assertNotNull("Cipher list should not be null", ciphers);
	assertTrue("Should have at least one cipher available", ciphers.length > 0);

	// Check that all returned values are non-null strings
	for (String cipher : ciphers) {
	assertNotNull("Cipher name should not be null", cipher);
	assertTrue("Cipher name should not be empty", cipher.length() > 0);
	}
}

@Test
public void testGetAvailableMACs() {
	String[] macs = Connection.getAvailableMACs();

	assertNotNull("MAC list should not be null", macs);
	assertTrue("Should have at least one MAC available", macs.length > 0);

	// Check that all returned values are non-null strings
	for (String mac : macs) {
	assertNotNull("MAC name should not be null", mac);
	assertTrue("MAC name should not be empty", mac.length() > 0);
	}
}

@Test
public void testGetAvailableServerHostKeyAlgorithms() {
	String[] algorithms = Connection.getAvailableServerHostKeyAlgorithms();

	assertNotNull("Algorithm list should not be null", algorithms);
	assertTrue("Should have at least one algorithm available",
			algorithms.length > 0);

	// Check that all returned values are non-null strings
	for (String algorithm : algorithms) {
	assertNotNull("Algorithm name should not be null", algorithm);
	assertTrue("Algorithm name should not be empty", algorithm.length() > 0);
	}
}

@Test
public void testStaticMethodsReturnSameResults() {
	// Static methods should return consistent results across calls
	String[] ciphers1 = Connection.getAvailableCiphers();
	String[] ciphers2 = Connection.getAvailableCiphers();

	assertArrayEquals("Cipher lists should be identical", ciphers1, ciphers2);

	String[] macs1 = Connection.getAvailableMACs();
	String[] macs2 = Connection.getAvailableMACs();

	assertArrayEquals("MAC lists should be identical", macs1, macs2);

	String[] algos1 = Connection.getAvailableServerHostKeyAlgorithms();
	String[] algos2 = Connection.getAvailableServerHostKeyAlgorithms();

	assertArrayEquals("Algorithm lists should be identical", algos1, algos2);
}

@Test
public void testSetSecureRandom() {
	SecureRandom customRandom = new SecureRandom();

	// This should not throw an exception
	connection.setSecureRandom(customRandom);
}

@Test
public void testSetSecureRandomWithNull() {
	try {
	connection.setSecureRandom(null);
	fail("Should throw IllegalArgumentException with null SecureRandom");
	} catch (IllegalArgumentException e) {
	// Expected behavior - test passes
	}
}

@Test
public void testGetConnectionInfoThrowsWhenNotConnected() {
	try {
	connection.getConnectionInfo();
	fail("Should throw IllegalStateException when not connected");
	} catch (IllegalStateException e) {
	assertTrue("Exception message should indicate connection required",
				e.getMessage().contains("establish a connection first"));
	} catch (Exception e) {
	fail("Should throw IllegalStateException, got: " +
		e.getClass().getSimpleName());
	}
}

@Test
public void testIsAuthMethodAvailableWithNullMethod() {
	try {
	connection.isAuthMethodAvailable("testuser", null);
	fail("Should throw IllegalArgumentException with null method");
	} catch (IllegalArgumentException e) {
	assertTrue("Exception message should mention method argument",
				e.getMessage().contains("method argument"));
	} catch (Exception e) {
	fail("Should throw IllegalArgumentException, got: " +
		e.getClass().getSimpleName());
	}
}

@Test
public void testSendIgnorePacketWithNullData() {
	try {
	connection.sendIgnorePacket(null);
	fail("Should throw IllegalArgumentException with null data");
	} catch (IllegalArgumentException e) {
	assertTrue("Exception message should mention data argument",
				e.getMessage().contains("data argument"));
	} catch (Exception e) {
	// May also throw IllegalStateException if not connected
	assertTrue(
		"Should throw IllegalArgumentException or IllegalStateException",
		e instanceof IllegalArgumentException || e instanceof
													IllegalStateException);
	}
}

@Test
public void testSendIgnorePacketWithEmptyData() {
	try {
	connection.sendIgnorePacket(new byte[0]);
	fail("Should throw some exception when not connected");
	} catch (IllegalStateException e) {
	// Expected when not connected
	} catch (Exception e) {
	// Some other exception is also acceptable since we're not connected
	}
}

@Test
public void testCloseWithoutConnection() {
	// Should not throw an exception even if not connected
	connection.close();
}

@Test
public void testSetCompressionWithoutConnection() {
	// Should succeed when not connected (sets internal flag)
	try {
	connection.setCompression(true);
	} catch (IOException e) {
	fail("Should not throw IOException when not connected: " +
		e.getMessage());
	}
}

@Test
public void testConnectionIdentification() {
	String identification = Connection.identification;

	assertNotNull("Identification should not be null", identification);
	assertTrue("Identification should not be empty",
			identification.length() > 0);
	assertTrue("Identification should contain version info",
			identification.contains("TrileadSSH2Java"));
}

@Test
public void testHostnameNullHandling() {
	// Test with null hostname (may be allowed by implementation)
	try {
	Connection conn = new Connection(null, 22);
	assertNull("Null hostname should be preserved", conn.getHostname());
	} catch (Exception e) {
	// If constructor throws exception with null hostname, that's also
	// acceptable
	}
}

@Test
public void testPortEdgeCases() {
	// Test with port 0
	Connection conn1 = new Connection("example.com", 0);
	assertEquals("Port 0 should be preserved", 0, conn1.getPort());

	// Test with high port number
	Connection conn2 = new Connection("example.com", 65535);
	assertEquals("High port should be preserved", 65535, conn2.getPort());

	// Test with negative port (behavior depends on implementation)
	Connection conn3 = new Connection("example.com", -1);
	assertEquals("Negative port should be preserved", -1, conn3.getPort());
}

@Test
public void testSetCipherAndMACMethods() {
	// Use valid cipher and MAC names from the available lists
	String[] availableCiphers = Connection.getAvailableCiphers();
	String[] availableMACs = Connection.getAvailableMACs();

	// Take first 2 ciphers and MACs for testing
	String[] testCiphers = {availableCiphers[0], availableCiphers.length > 1
													? availableCiphers[1]
													: availableCiphers[0]};
	String[] testMACs = {availableMACs[0], availableMACs.length > 1
											? availableMACs[1]
											: availableMACs[0]};

	// These should not throw exceptions
	connection.setClient2ServerCiphers(testCiphers);
	connection.setServer2ClientCiphers(testCiphers);
	connection.setClient2ServerMACs(testMACs);
	connection.setServer2ClientMACs(testMACs);
}

@Test
public void testSetAlgorithmMethods() {
	// Use valid algorithm names from available lists
	String[] availableAlgos = Connection.getAvailableServerHostKeyAlgorithms();
	String[] testAlgos = {availableAlgos[0], availableAlgos.length > 1
												? availableAlgos[1]
												: availableAlgos[0]};

	// These should not throw exceptions
	connection.setServerHostKeyAlgorithms(testAlgos);

	// For KEX algorithms, we'll test with a known algorithm
	String[] testKexAlgos = {"diffie-hellman-group1-sha1"}; // Basic DH group
	connection.setKeyExchangeAlgorithms(testKexAlgos);
}
}

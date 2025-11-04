package com.trilead.ssh2;

/**
 * Utility class for checking ML-KEM (JEP-496) availability.
 *
 * @author Kenny Root
 */
public final class MlKemAvailability {
	private static final String REQUIRE_MLKEM_PROPERTY = "ssh.test.require.mlkem";
	private static final String REQUIRE_MLKEM_ENV = "SSH_TEST_REQUIRE_MLKEM";

	private MlKemAvailability() {
	}

	/**
	 * Checks if ML-KEM-768 support is available in the current JDK.
	 * This requires Java 23 or later with JEP-496 support.
	 *
	 * <p>If the system property "ssh.test.require.mlkem" or environment variable
	 * "SSH_TEST_REQUIRE_MLKEM" is set to "true", this method will throw an
	 * AssertionError if ML-KEM is not available. This is useful for CI environments
	 * to ensure ML-KEM support is properly configured.
	 *
	 * @return true if ML-KEM is available, false otherwise
	 * @throws AssertionError if ML-KEM is required but not available
	 */
	public static boolean isAvailable() {
		boolean available = checkAvailability();
		boolean required = isRequired();

		if (required && !available) {
			throw new AssertionError(
					"ML-KEM support is required (via " + REQUIRE_MLKEM_PROPERTY
							+ " or " + REQUIRE_MLKEM_ENV + ") but not available. "
							+ "Ensure Java 23+ with JEP-496 support is being used.");
		}

		return available;
	}

	private static boolean checkAvailability() {
		try {
			Class.forName("javax.crypto.KEM");
			java.security.KeyPairGenerator.getInstance("ML-KEM-768");
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	private static boolean isRequired() {
		String sysProp = System.getProperty(REQUIRE_MLKEM_PROPERTY);
		if (sysProp != null) {
			return Boolean.parseBoolean(sysProp);
		}

		String envVar = System.getenv(REQUIRE_MLKEM_ENV);
		if (envVar != null) {
			return Boolean.parseBoolean(envVar);
		}

		return false;
	}
}

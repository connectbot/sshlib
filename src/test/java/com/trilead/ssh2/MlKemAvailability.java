package com.trilead.ssh2;

/**
 * Utility class for checking ML-KEM (JEP-496) availability.
 *
 * @author Kenny Root
 */
public final class MlKemAvailability {
	private MlKemAvailability() {
	}

	/**
	 * Checks if ML-KEM-768 support is available in the current JDK.
	 * This requires either Java 23+ with JEP-496 support or Kyber Kotlin library.
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

		if (!available) {
			throw new AssertionError(
					"ML-KEM support is required but not available. "
							+ "Ensure Java 23+ with JEP-496 support or Kyber Kotlin library is present.");
		}

		return available;
	}

	private static boolean checkAvailability() {
		try {
			Class.forName("javax.crypto.KEM");
			java.security.KeyPairGenerator.getInstance("ML-KEM-768");
			return true;
		} catch (Exception e) {
			try {
				Class.forName("asia.hombre.kyber.KyberKeyGenerator");
				return true;
			} catch (ClassNotFoundException e2) {
				return false;
			}
		}
	}
}

package com.trilead.ssh2.crypto.dh;

import com.trilead.ssh2.log.Logger;

import java.security.KeyPairGenerator;

/**
 * Factory for creating X25519Provider instances.
 * Automatically selects the platform-native implementation when available (Java 11+/Android API 33+),
 * falling back to Tink otherwise.
 */
public class X25519ProviderFactory {
	private static final Logger log = Logger.getLogger(X25519ProviderFactory.class);
	private static final X25519Provider INSTANCE;
	private static final boolean PLATFORM_NATIVE_AVAILABLE;

	static {
		X25519Provider provider = null;
		boolean platformNative = false;

		if (isPlatformNativeAvailable()) {
			try {
				provider = createPlatformProvider();
				platformNative = true;
				if (log.isEnabled()) {
					log.log(20, "Using platform-native X25519 implementation");
				}
			} catch (NoClassDefFoundError | Exception e) {
				if (log.isEnabled()) {
					log.log(20, "Platform X25519 class loading failed, falling back to Tink");
				}
			}
		}

		if (provider == null) {
			provider = new TinkX25519Provider();
			if (log.isEnabled()) {
				log.log(20, "Using Tink X25519 implementation");
			}
		}

		INSTANCE = provider;
		PLATFORM_NATIVE_AVAILABLE = platformNative;
	}

	private static boolean isPlatformNativeAvailable() {
		try {
			KeyPairGenerator.getInstance("X25519");
			Class.forName("java.security.spec.XECPrivateKeySpec");
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	private static X25519Provider createPlatformProvider() {
		return new PlatformX25519Provider();
	}

	public static X25519Provider getProvider() {
		return INSTANCE;
	}

	public static boolean isPlatformNative() {
		return PLATFORM_NATIVE_AVAILABLE;
	}

	public static X25519Provider getTinkProvider() {
		return new TinkX25519Provider();
	}

	public static X25519Provider getPlatformProvider() {
		if (!PLATFORM_NATIVE_AVAILABLE) {
			throw new UnsupportedOperationException("Platform-native X25519 not available");
		}
		return new PlatformX25519Provider();
	}
}

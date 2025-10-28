package com.trilead.ssh2.crypto.keys;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;

/**
 * JCA Provider for Ed25519 cryptographic operations.
 * <p>
 * Registers KeyFactory and KeyPairGenerator implementations for the
 * Ed25519 signature algorithm with the Java security framework.
 *
 * @see Ed25519KeyFactory
 * @see Ed25519KeyPairGenerator
 */
public class Ed25519Provider extends Provider {
	public static final String NAME = "ConnectBot Ed25519 Provider";
	public static final String KEY_ALGORITHM = "Ed25519";
	private static final Object sInitLock = new Object();
	private static boolean sInitialized = false;

	public Ed25519Provider() {
		super(NAME, "1.0", "Not for use elsewhere");
		AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
			setup();
			return null;
		});
	}

	protected void setup() {
		put("KeyFactory." + KEY_ALGORITHM, getClass().getPackage().getName() + ".Ed25519KeyFactory");
		put("KeyPairGenerator." + KEY_ALGORITHM, getClass().getPackage().getName() + ".Ed25519KeyPairGenerator");

		//   id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
		put("Alg.Alias.KeyFactory.1.3.101.112", KEY_ALGORITHM);
		put("Alg.Alias.KeyFactory.EdDSA", KEY_ALGORITHM);
		put("Alg.Alias.KeyFactory.OID.1.3.101.112", KEY_ALGORITHM);
		put("Alg.Alias.KeyPairGenerator.1.3.101.112", KEY_ALGORITHM);
		put("Alg.Alias.KeyPairGenerator.EdDSA", KEY_ALGORITHM);
		put("Alg.Alias.KeyPairGenerator.OID.1.3.101.112", KEY_ALGORITHM);
	}

	public static void insertIfNeeded() {
		synchronized (sInitLock) {
			if (!sInitialized) {
				Security.insertProviderAt(new Ed25519Provider(), 1);
				sInitialized = true;
			}
		}
	}
}

package com.trilead.ssh2.crypto.keys;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public class EdDSAProvider extends Provider {
	public static final String KEY_ALGORITHM = "EdDSA";

	public EdDSAProvider() {
		super("ConnectBot EdDSA Provider", 1.0, "Not for use elsewhere");
		AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
			setup();
			return null;
		});
	}

	protected void setup() {
		put("KeyFactory." + KEY_ALGORITHM, getClass().getPackage().getName() + ".EdDSAKeyFactory");
		put("KeyPairGenerator." + KEY_ALGORITHM, getClass().getPackage().getName() + ".EdDSAKeyPairGenerator");

		//   id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
		put("Alg.Alias.KeyFactory.1.3.101.112", KEY_ALGORITHM);
		put("Alg.Alias.KeyFactory.OID.1.3.101.112", KEY_ALGORITHM);
		put("Alg.Alias.KeyPairGenerator.1.3.101.112", KEY_ALGORITHM);
		put("Alg.Alias.KeyPairGenerator.OID.1.3.101.112", KEY_ALGORITHM);
	}
}

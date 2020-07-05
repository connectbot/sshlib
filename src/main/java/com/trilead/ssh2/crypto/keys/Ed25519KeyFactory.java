package com.trilead.ssh2.crypto.keys;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Ed25519KeyFactory extends KeyFactorySpi {
	@Override
	protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
		if (keySpec instanceof X509EncodedKeySpec) {
			return new Ed25519PublicKey((X509EncodedKeySpec) keySpec);
		}
		throw new InvalidKeySpecException("Unrecognized key spec: " + keySpec.getClass());
	}

	@Override
	protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
		if (keySpec instanceof PKCS8EncodedKeySpec) {
			return new Ed25519PrivateKey((PKCS8EncodedKeySpec) keySpec);
		}
		throw new InvalidKeySpecException("Unrecognized key spec: " + keySpec.getClass());
	}

	@Override
	protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
		throw new InvalidKeySpecException("not implemented yet " + key + " " + keySpec);
	}

	@Override
	protected Key engineTranslateKey(Key key) throws InvalidKeyException {
		throw new InvalidKeyException("No other EdDSA key providers known");
	}
}

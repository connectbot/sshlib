package com.trilead.ssh2.crypto.keys;

import java.security.PublicKey;

public class EdDSAPublicKey implements PublicKey {
	private final byte[] keyBytes;

	public EdDSAPublicKey(byte[] keyBytes) {
		this.keyBytes = keyBytes;
	}

	@Override
	public String getAlgorithm() {
		return "EdDSA";
	}

	@Override
	public String getFormat() {
		return "RAW";
	}

	@Override
	public byte[] getEncoded() {
		return keyBytes;
	}
}

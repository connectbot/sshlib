package com.trilead.ssh2.crypto.keys;

import java.security.PrivateKey;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;

public class EdDSAPrivateKey implements PrivateKey {
	private final byte[] keyBytes;
	private boolean destroyed;

	public EdDSAPrivateKey(byte[] keyBytes) {
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

	@Override
	public void destroy() throws DestroyFailedException {
		Arrays.fill(keyBytes, (byte) 0);
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}
}

package com.trilead.ssh2.crypto.dh;

import djb.Curve25519;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Kenny Root on 1/23/16.
 */
public class Curve25519Exchange extends GenericDhExchange {
	public static final String NAME = "curve25519-sha256";
	public static final String ALT_NAME = "curve25519-sha256@libssh.org";

	private final byte[] clientPublic = new byte[Curve25519.KEY_SIZE];
	private final byte[] clientPrivate = new byte[Curve25519.KEY_SIZE];
	private final byte[] serverPublic = new byte[Curve25519.KEY_SIZE];

	public Curve25519Exchange() {
		super();
	}

	/*
	 * Used to test known vectors.
	 */
	public Curve25519Exchange(byte[] secret) {
		if (secret.length != Curve25519.KEY_SIZE) {
			throw new AssertionError("secret must be key size");
		}
		System.arraycopy(secret, 0, clientPrivate, 0, secret.length);
		Curve25519.keygen(clientPublic, null, clientPrivate);
	}

	@Override
	public void init(String name) throws IOException {
		if (!NAME.equals(name) && !ALT_NAME.equals(name)) {
			throw new IOException("Invalid name " + name);
		}

		SecureRandom sr = new SecureRandom();
		sr.nextBytes(clientPrivate);
		Curve25519.keygen(clientPublic, null, clientPrivate);
	}

	@Override
	public byte[] getE() {
		return clientPublic.clone();
	}

	@Override
	protected byte[] getServerE() {
		return serverPublic.clone();
	}

	@Override
	public void setF(byte[] f) throws IOException {
		if (f.length != serverPublic.length) {
			throw new IOException("Server sent invalid key length " + f.length + " (expected " +
					serverPublic.length + ")");
		}
		System.arraycopy(f, 0, serverPublic, 0, f.length);
		byte[] sharedSecretBytes = new byte[Curve25519.KEY_SIZE];
		Curve25519.curve(sharedSecretBytes, clientPrivate, serverPublic);
		sharedSecret = new BigInteger(1, sharedSecretBytes);
	}

	@Override
	public String getHashAlgo() {
		return "SHA-256";
	}
}

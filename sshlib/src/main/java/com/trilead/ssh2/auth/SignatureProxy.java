/*
 * Copyright 2017 Jonas Dippel, Michael Perk, Marc Totzke
 */

package com.trilead.ssh2.auth;

import java.io.IOException;
import java.security.PublicKey;

public abstract class SignatureProxy
{
	public static final String SHA1 = "SHA-1";
	public static final String SHA256 = "SHA-256";
	public static final String SHA384 = "SHA-384";
	public static final String SHA512 = "SHA-512";

	/**
	 * Holds the public key which belongs to the private key which is used in the signing process.
	 */
	private PublicKey mPublicKey;

	/**
	 * Instantiates a new SignatureProxy which needs a public key for the
	 * later authentication process.
	 *
	 * @param publicKey The public key.
	 * @throws IllegalArgumentException Might be thrown id the public key is invalid.
	 */
	public SignatureProxy(PublicKey publicKey)
	{
		if (publicKey == null)
		{
			throw new IllegalArgumentException("Public key must not be null");
		}
		mPublicKey = publicKey;
	}

	/**
	 * This method should sign a given byte array message using the private key.
	 *
	 * @param message The message which should be signed.
	 * @param hashAlgorithm The hashing algorithm which should be used.
	 * @return The signed message.
	 * @throws IOException This exception might be thrown during the signing process.
	 */
	public abstract byte[] sign(byte[] message, String hashAlgorithm) throws IOException;

	public PublicKey getPublicKey()
	{
		return mPublicKey;
	}
}

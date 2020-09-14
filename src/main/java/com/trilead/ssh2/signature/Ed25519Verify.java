/*
 * Copyright 2015 Kenny Root
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * a.) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * b.) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * c.) Neither the name of Trilead nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.trilead.ssh2.signature;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.trilead.ssh2.crypto.keys.Ed25519PrivateKey;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;
import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * @author Kenny Root
 */
public class Ed25519Verify implements SSHSignature {
	private static final Logger log = Logger.getLogger(Ed25519Verify.class);

	/** Identifies this as an Ed25519 key in the protocol. */
	public static final String ED25519_ID = "ssh-ed25519";

	private static final int ED25519_PK_SIZE_BYTES = 32;
	private static final int ED25519_SIG_SIZE_BYTES = 64;

	private static class InstanceHolder {
		private static final Ed25519Verify sInstance = new Ed25519Verify();
	}

	private Ed25519Verify() {
	}

	public static Ed25519Verify get() {
		return Ed25519Verify.InstanceHolder.sInstance;
	}

	@Override
	public byte[] encodePublicKey(PublicKey publicKey) {
		Ed25519PublicKey ed25519PublicKey = (Ed25519PublicKey) publicKey;

		TypesWriter tw = new TypesWriter();

		tw.writeString(ED25519_ID);
		byte[] encoded = ed25519PublicKey.getAbyte();
		tw.writeString(encoded, 0, encoded.length);

		return tw.getBytes();
	}

	@Override
	public PublicKey decodePublicKey(byte[] encoded) throws IOException {
		TypesReader tr = new TypesReader(encoded);

		String key_format = tr.readString();
		if (!key_format.equals(ED25519_ID)) {
			throw new IOException("This is not an Ed25519 key");
		}

		byte[] keyBytes = tr.readByteString();

		if (tr.remain() != 0) {
			throw new IOException("Padding in Ed25519 public key! " + tr.remain() + " bytes left.");
		}

		if (keyBytes.length != ED25519_PK_SIZE_BYTES) {
			throw new IOException("Ed25519 was not of correct length: " + keyBytes.length + " vs " + ED25519_PK_SIZE_BYTES);
		}

		return new Ed25519PublicKey(keyBytes);
	}

	@Override
	public byte[] generateSignature(byte[] msg, PrivateKey privateKey, SecureRandom secureRandom) throws IOException {
		Ed25519PrivateKey ed25519PrivateKey = (Ed25519PrivateKey) privateKey;
		try {
			return encodeSSHEd25519Signature(new Ed25519Sign(ed25519PrivateKey.getSeed()).sign(msg));
		} catch (GeneralSecurityException e) {
			throw new IOException(e);
		}
	}

	@Override
	public boolean verifySignature(byte[] message, byte[] sshSig, PublicKey publicKey) throws IOException {
		Ed25519PublicKey ed25519PublicKey = (Ed25519PublicKey) publicKey;
		byte[] javaSig = decodeSSHEd25519Signature(sshSig);
		try {
			new com.google.crypto.tink.subtle.Ed25519Verify(ed25519PublicKey.getAbyte()).verify(javaSig, message);
			return true;
		} catch (GeneralSecurityException e) {
			return false;
		}
	}

	private static byte[] encodeSSHEd25519Signature(byte[] sig) {
		TypesWriter tw = new TypesWriter();

		tw.writeString(ED25519_ID);
		tw.writeString(sig, 0, sig.length);

		return tw.getBytes();
	}

	private static byte[] decodeSSHEd25519Signature(byte[] sig) throws IOException {
		byte[] rsArray;

		TypesReader tr = new TypesReader(sig);

		String sig_format = tr.readString();
		if (!sig_format.equals(ED25519_ID)) {
			throw new IOException("Peer sent wrong signature format");
		}

		rsArray = tr.readByteString();

		if (tr.remain() != 0) {
			throw new IOException("Padding in Ed25519 signature!");
		}

		if (rsArray.length > ED25519_SIG_SIZE_BYTES) {
			throw new IOException("Ed25519 signature was " + rsArray.length + " bytes (" + ED25519_PK_SIZE_BYTES + " expected)");
		}

		return rsArray;
	}

	@Override
	public String getKeyFormat() {
		return ED25519_ID;
	}
}

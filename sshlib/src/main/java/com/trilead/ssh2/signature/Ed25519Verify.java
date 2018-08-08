/*
 * ConnectBot: simple, powerful, open-source SSH client for Android
 * Copyright 2015 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.trilead.ssh2.signature;

import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * @author Kenny Root
 */
public class Ed25519Verify {
	private static final Logger log = Logger.getLogger(Ed25519Verify.class);

	/** Identifies this as an Ed25519 key in the protocol. */
	public static final String ED25519_ID = "ssh-ed25519";

	public static final String ED25519_CURVE_NAME = "Ed25519";

	private static final int ED25519_PK_SIZE_BYTES = 32;
	private static final int ED25519_SIG_SIZE_BYTES = 64;

	public static byte[] encodeSSHEd25519PublicKey(EdDSAPublicKey key) {
		TypesWriter tw = new TypesWriter();

		tw.writeString(ED25519_ID);
		byte[] encoded = key.getAbyte();
		tw.writeString(encoded, 0, encoded.length);

		return tw.getBytes();
	}

	public static EdDSAPublicKey decodeSSHEd25519PublicKey(byte[] key) throws IOException {
		TypesReader tr = new TypesReader(key);

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

		return new EdDSAPublicKey(new EdDSAPublicKeySpec(keyBytes, EdDSANamedCurveTable.getByName(ED25519_CURVE_NAME)));
	}

	public static byte[] generateSignature(byte[] msg, EdDSAPrivateKey privateKey) throws IOException {
		try {
			EdDSAEngine engine = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
			engine.setParameter(EdDSAEngine.ONE_SHOT_MODE);
			engine.initSign(privateKey);
			engine.update(msg);
			return engine.sign();
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		} catch (SignatureException e) {
			throw new IOException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IOException(e);
		} catch (InvalidKeyException e) {
			throw new IOException(e);
		}
	}

	public static boolean verifySignature(byte[] msg, byte[] sig, EdDSAPublicKey publicKey) throws IOException {
		try {
			EdDSAEngine engine = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
			engine.initVerify(publicKey);
			engine.setParameter(EdDSAEngine.ONE_SHOT_MODE);
			engine.update(msg);
			return engine.verify(sig);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IOException(e);
		} catch (InvalidKeyException e) {
			throw new IOException(e);
		} catch (SignatureException e) {
			throw new IOException(e);
		}
	}

	public static byte[] encodeSSHEd25519Signature(byte[] sig) {
		TypesWriter tw = new TypesWriter();

		tw.writeString(ED25519_ID);
		tw.writeString(sig, 0, sig.length);

		return tw.getBytes();
	}

	public static byte[] decodeSSHEd25519Signature(byte[] sig) throws IOException {
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
}

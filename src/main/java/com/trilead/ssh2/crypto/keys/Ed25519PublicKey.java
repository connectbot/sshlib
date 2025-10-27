package com.trilead.ssh2.crypto.keys;

import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Ed25519 public key implementation for SSH.
 * <p>
 * Supports X.509 encoding for use in SSH authentication and signature verification.
 *
 * @see Ed25519PrivateKey
 * @see Ed25519KeyFactory
 */
public class Ed25519PublicKey implements PublicKey {
	private static final byte[] ED25519_OID = new byte[]{43, 101, 112};
	private static final int KEY_BYTES_LENGTH = 32;
	private static final int ENCODED_SIZE = 44;

	private final byte[] keyBytes;

	public Ed25519PublicKey(byte[] keyBytes) {
		this.keyBytes = keyBytes;
	}

	public Ed25519PublicKey(X509EncodedKeySpec keySpec) throws InvalidKeySpecException {
		keyBytes = decode(keySpec.getEncoded());
	}

	@Override
	public String getAlgorithm() {
		return "EdDSA";
	}

	@Override
	public String getFormat() {
		return "X.509";
	}

	@Override
	public byte[] getEncoded() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0x30); // ASN.1 sequence
		tw.writeByte(7 + ED25519_OID.length + keyBytes.length);
		// Algorithm identifier
		tw.writeByte(0x30); // ASN.1 sequence
		tw.writeByte(2 + ED25519_OID.length);
		tw.writeByte(0x06); // ASN.1 OID
		tw.writeByte(ED25519_OID.length);
		tw.writeBytes(ED25519_OID);
		// Public key
		tw.writeByte(0x03); // ASN.1 bit string
		tw.writeByte(keyBytes.length + 1);
		tw.writeByte(0);
		tw.writeBytes(keyBytes);
		return tw.getBytes();
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(keyBytes);
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof Ed25519PublicKey)) {
			return false;
		}

		Ed25519PublicKey other = (Ed25519PublicKey) o;
		if (keyBytes == null || other.keyBytes == null) {
			return false;
		}

		return Arrays.equals(keyBytes, other.keyBytes);
	}

	private static byte[] decode(byte[] input) throws InvalidKeySpecException {
		if (input.length != ENCODED_SIZE) {
			throw new InvalidKeySpecException("Key is not of correct size");
		}

		try {
			TypesReader tr = new TypesReader(input);
			if (tr.readByte() != 0x30 ||
				tr.readByte() != 7 + ED25519_OID.length + KEY_BYTES_LENGTH ||
				tr.readByte() != 0x30 ||
				tr.readByte() != 2 + ED25519_OID.length ||
				tr.readByte() != 0x06 ||
				tr.readByte() != ED25519_OID.length) {
				throw new InvalidKeySpecException("Key was not encoded correctly");
			}
			byte[] oid = tr.readBytes(ED25519_OID.length);
			if (!Arrays.equals(oid, ED25519_OID) ||
				tr.readByte() != 0x03 ||
				tr.readByte() != KEY_BYTES_LENGTH + 1 ||
				tr.readByte() != 0) {
				throw new InvalidKeySpecException("Key was not encoded correctly");
			}
			return tr.readBytes(KEY_BYTES_LENGTH);
		} catch (IOException e) {
			throw new InvalidKeySpecException("Key was not encoded correctly");
		}
	}

	public byte[] getAbyte() {
		return keyBytes;
	}
}

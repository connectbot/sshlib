package com.trilead.ssh2.crypto.keys;

import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;

public class Ed25519PrivateKey implements PrivateKey {
	private static final byte[] ED25519_OID = new byte[] {43, 101, 112};
	private static final int KEY_BYTES_LENGTH = 32;
	private static final int ENCODED_SIZE = 48;

	private final byte[] seed;
	private boolean destroyed;

	public Ed25519PrivateKey(byte[] hash) {
		this.seed = hash;
	}

	public Ed25519PrivateKey(PKCS8EncodedKeySpec keySpec) throws InvalidKeySpecException {
		this.seed = decode(keySpec);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(seed);
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof Ed25519PrivateKey)) {
			return false;
		}

		Ed25519PrivateKey other = (Ed25519PrivateKey) o;

		if (seed == null || other.seed == null || seed.length != other.seed.length) {
			return false;
		}

		int difference = 0;
		for (int i = 0; i < seed.length; i++) {
			difference |= seed[i] ^ other.seed[i];
		}
		return difference == 0;
	}

	@Override
	public String getAlgorithm() {
		return "EdDSA";
	}

	@Override
	public String getFormat() {
		return "PKCS#8";
	}

	public byte[] getSeed() {
		return seed;
	}

	@Override
	public byte[] getEncoded() {
		// From RFC 8410 section 7 "Private Key Format"
		TypesWriter tw = new TypesWriter();
		// ASN.1 Sequence
		tw.writeByte(0x30);
		tw.writeByte(11 + ED25519_OID.length + seed.length); // Length
		// Key version type
		tw.writeByte(0x02); // ASN.1 Integer
		tw.writeByte(1); // Length
		tw.writeByte(0); // v1 == RFC 5208 format
		// Algorithm OID - ASN.1 Sequence
		tw.writeByte(0x30);
		tw.writeByte(ED25519_OID.length + 2); // OID
		tw.writeByte(0x06); // ASN.1 OID type
		tw.writeByte(ED25519_OID.length);
		tw.writeBytes(ED25519_OID);
		// Private key sequence
		tw.writeByte(0x04); // ASN.1 Octet string
		tw.writeByte(2 + seed.length);
		tw.writeByte(0x04); // ASN.1 Octet string
		tw.writeByte(seed.length);
		tw.writeBytes(seed);

		return tw.getBytes();
	}

	private static byte[] decode(PKCS8EncodedKeySpec keySpec) throws InvalidKeySpecException {
		byte[] encoded = keySpec.getEncoded();
		if (encoded.length != ENCODED_SIZE) {
			throw new InvalidKeySpecException("Key spec is of invalid size");
		}
		try {
			TypesReader tr = new TypesReader(keySpec.getEncoded());
			if (tr.readByte() != 0x30 || // ASN.1 sequence
				tr.readByte() != ENCODED_SIZE - 2 || // Expected size
				tr.readByte() != 0x02 || // ASN.1 Integer
				tr.readByte() != 1 || // length
				tr.readByte() != 0 || // v1
				tr.readByte() != 0x30 || // ASN.1 Sequence
				tr.readByte() != ED25519_OID.length + 2 || // OID length
				tr.readByte() != 0x06 || // ASN.1 OID
				tr.readByte() != ED25519_OID.length) {
				throw new InvalidKeySpecException("Key was not encoded correctly");
			}
			byte[] oid = tr.readBytes(ED25519_OID.length);
			if (!Arrays.equals(ED25519_OID, oid) ||
				tr.readByte() != 0x04 || // ASN.1 octet string
				tr.readByte() != KEY_BYTES_LENGTH + 2 || // length
				tr.readByte() != 0x04 || // ASN.1 octet string
				tr.readByte() != KEY_BYTES_LENGTH) {
				throw new InvalidKeySpecException("Key was not encoded correctly");
			}
			return tr.readBytes(KEY_BYTES_LENGTH);
		} catch (IOException e) {
			throw new InvalidKeySpecException("Key was not encoded correctly", e);
		}
	}

	@Override
	public void destroy() throws DestroyFailedException {
		Arrays.fill(seed, (byte) 0);
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}
}

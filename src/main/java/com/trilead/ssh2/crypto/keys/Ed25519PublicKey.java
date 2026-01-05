package com.trilead.ssh2.crypto.keys;

import com.trilead.ssh2.crypto.SimpleDERReader;
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
		// Handle legacy RAW format (32 bytes) from commits f01a8b9 to 91bf5d0 (May-July 2020)
		// Before commit 91bf5d0, getEncoded() returned just the raw 32-byte public key with format "RAW"
		if (input.length == KEY_BYTES_LENGTH) {
			return input;
		}

		// Handle standard X.509 format (44 bytes) from commit 91bf5d0 onwards
		try {
			SimpleDERReader reader = new SimpleDERReader(input);

			byte[] sequenceData = reader.readSequenceAsByteArray();
			SimpleDERReader sequenceReader = new SimpleDERReader(sequenceData);

			int algType = sequenceReader.readConstructedType();
			SimpleDERReader algReader = sequenceReader.readConstructed();

			String oid = algReader.readOid();
			if (!"1.3.101.112".equals(oid)) {
				throw new InvalidKeySpecException("Expected Ed25519 OID (1.3.101.112), got: " + oid);
			}

			byte[] publicKeyBitString = sequenceReader.readOctetString();

			if (publicKeyBitString.length == KEY_BYTES_LENGTH + 1 && publicKeyBitString[0] == 0) {
				byte[] result = new byte[KEY_BYTES_LENGTH];
				System.arraycopy(publicKeyBitString, 1, result, 0, KEY_BYTES_LENGTH);
				return result;
			} else if (publicKeyBitString.length == KEY_BYTES_LENGTH) {
				return publicKeyBitString;
			} else {
				throw new InvalidKeySpecException("Expected " + KEY_BYTES_LENGTH + " byte public key, got " + publicKeyBitString.length);
			}
		} catch (IOException e) {
			throw new InvalidKeySpecException("Key was not encoded correctly", e);
		}
	}

	public byte[] getAbyte() {
		return keyBytes;
	}
}

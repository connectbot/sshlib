package com.trilead.ssh2.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * SimpleDERWriter - counterpart to SimpleDERReader for encoding DER structures.
 *
 * @author Kenny Root
 */
public class SimpleDERWriter {
	private final ByteArrayOutputStream buffer;

	public SimpleDERWriter() {
		this.buffer = new ByteArrayOutputStream();
	}

	public void writeByte(byte b) {
		buffer.write(b);
	}

	public void writeBytes(byte[] b) {
		buffer.write(b, 0, b.length);
	}

	public void writeLength(int length) throws IOException {
		if (length < 0) {
			throw new IOException("Length cannot be negative");
		}

		if (length < 128) {
			writeByte((byte) length);
		} else if (length < 256) {
			writeByte((byte) 0x81);
			writeByte((byte) length);
		} else if (length < 65536) {
			writeByte((byte) 0x82);
			writeByte((byte) (length >> 8));
			writeByte((byte) length);
		} else if (length < 16777216) {
			writeByte((byte) 0x83);
			writeByte((byte) (length >> 16));
			writeByte((byte) (length >> 8));
			writeByte((byte) length);
		} else {
			writeByte((byte) 0x84);
			writeByte((byte) (length >> 24));
			writeByte((byte) (length >> 16));
			writeByte((byte) (length >> 8));
			writeByte((byte) length);
		}
	}

	public void writeInt(BigInteger value) throws IOException {
		writeByte((byte) 0x02);

		byte[] bytes = value.toByteArray();
		writeLength(bytes.length);
		writeBytes(bytes);
	}

	public void writeSequence(byte[] data) throws IOException {
		writeByte((byte) 0x30);
		writeLength(data.length);
		writeBytes(data);
	}

	public void writeOid(String oid) throws IOException {
		writeByte((byte) 0x06);

		String[] parts = oid.split("\\.");
		if (parts.length < 2) {
			throw new IOException("Invalid OID format");
		}

		ByteArrayOutputStream oidBytes = new ByteArrayOutputStream();

		int first = Integer.parseInt(parts[0]);
		int second = Integer.parseInt(parts[1]);
		oidBytes.write(first * 40 + second);

		for (int i = 2; i < parts.length; i++) {
			long value = Long.parseLong(parts[i]);
			encodeOidComponent(oidBytes, value);
		}

		byte[] encoded = oidBytes.toByteArray();
		writeLength(encoded.length);
		writeBytes(encoded);
	}

	private void encodeOidComponent(ByteArrayOutputStream out, long value) {
		if (value < 128) {
			out.write((int) value);
		} else {
			int numBytes = 0;
			long temp = value;
			while (temp > 0) {
				numBytes++;
				temp >>= 7;
			}

			for (int i = numBytes - 1; i >= 0; i--) {
				int byteVal = (int) ((value >> (i * 7)) & 0x7F);
				if (i > 0) {
					byteVal |= 0x80;
				}
				out.write(byteVal);
			}
		}
	}

	public void writeOctetString(byte[] data) throws IOException {
		writeByte((byte) 0x04);
		writeLength(data.length);
		writeBytes(data);
	}

	public void writeBitString(byte[] data) throws IOException {
		writeByte((byte) 0x03);
		writeLength(data.length + 1);
		writeByte((byte) 0x00);
		writeBytes(data);
	}

	public byte[] getBytes() {
		return buffer.toByteArray();
	}
}

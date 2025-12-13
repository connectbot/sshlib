package com.trilead.ssh2.crypto;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SimpleDERWriterTest {

	@Test
	void testWriteInt() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		writer.writeInt(BigInteger.valueOf(42));

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		BigInteger result = reader.readInt();

		assertEquals(BigInteger.valueOf(42), result);
	}

	@Test
	void testWriteLargeInt() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		BigInteger large = new BigInteger("123456789012345678901234567890");
		writer.writeInt(large);

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		BigInteger result = reader.readInt();

		assertEquals(large, result);
	}

	@Test
	void testWriteZero() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		writer.writeInt(BigInteger.ZERO);

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		BigInteger result = reader.readInt();

		assertEquals(BigInteger.ZERO, result);
	}

	@Test
	void testWriteOid() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		String oid = "1.2.840.10045.2.1";
		writer.writeOid(oid);

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		String result = reader.readOid();

		assertEquals(oid, result);
	}

	@Test
	void testWriteOidRsaEncryption() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		String oid = "1.2.840.113549.1.1.1";
		writer.writeOid(oid);

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		String result = reader.readOid();

		assertEquals(oid, result);
	}

	@Test
	void testWriteOctetString() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
		writer.writeOctetString(data);

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		byte[] result = reader.readOctetString();

		assertArrayEquals(data, result);
	}

	@Test
	void testWriteEmptyOctetString() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		byte[] data = new byte[0];
		writer.writeOctetString(data);

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		byte[] result = reader.readOctetString();

		assertArrayEquals(data, result);
	}

	@Test
	void testWriteSequence() throws IOException {
		SimpleDERWriter inner = new SimpleDERWriter();
		inner.writeInt(BigInteger.valueOf(123));
		inner.writeInt(BigInteger.valueOf(456));

		SimpleDERWriter outer = new SimpleDERWriter();
		outer.writeSequence(inner.getBytes());

		byte[] encoded = outer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		byte[] sequenceData = reader.readSequenceAsByteArray();
		SimpleDERReader innerReader = new SimpleDERReader(sequenceData);

		assertEquals(BigInteger.valueOf(123), innerReader.readInt());
		assertEquals(BigInteger.valueOf(456), innerReader.readInt());
	}

	@Test
	void testWriteMultipleElements() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		writer.writeInt(BigInteger.valueOf(100));
		writer.writeOid("1.2.3.4");
		writer.writeOctetString(new byte[] { (byte) 0xAA, (byte) 0xBB });

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);

		assertEquals(BigInteger.valueOf(100), reader.readInt());
		assertEquals("1.2.3.4", reader.readOid());
		assertArrayEquals(new byte[] { (byte) 0xAA, (byte) 0xBB }, reader.readOctetString());
	}

	@Test
	void testWriteLongLength() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		byte[] longData = new byte[256];
		for (int i = 0; i < longData.length; i++) {
			longData[i] = (byte) i;
		}
		writer.writeOctetString(longData);

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		byte[] result = reader.readOctetString();

		assertArrayEquals(longData, result);
	}

	@Test
	void testWriteVeryLongLength() throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		byte[] veryLongData = new byte[300];
		for (int i = 0; i < veryLongData.length; i++) {
			veryLongData[i] = (byte) (i % 256);
		}
		writer.writeOctetString(veryLongData);

		byte[] encoded = writer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);
		byte[] result = reader.readOctetString();

		assertArrayEquals(veryLongData, result);
	}

	@Test
	void testNestedSequences() throws IOException {
		SimpleDERWriter innermost = new SimpleDERWriter();
		innermost.writeInt(BigInteger.valueOf(789));

		SimpleDERWriter middle = new SimpleDERWriter();
		middle.writeInt(BigInteger.valueOf(456));
		middle.writeSequence(innermost.getBytes());

		SimpleDERWriter outer = new SimpleDERWriter();
		outer.writeInt(BigInteger.valueOf(123));
		outer.writeSequence(middle.getBytes());

		byte[] encoded = outer.getBytes();
		SimpleDERReader reader = new SimpleDERReader(encoded);

		assertEquals(BigInteger.valueOf(123), reader.readInt());
		byte[] middleData = reader.readSequenceAsByteArray();
		SimpleDERReader middleReader = new SimpleDERReader(middleData);

		assertEquals(BigInteger.valueOf(456), middleReader.readInt());
		byte[] innermostData = middleReader.readSequenceAsByteArray();
		SimpleDERReader innermostReader = new SimpleDERReader(innermostData);

		assertEquals(BigInteger.valueOf(789), innermostReader.readInt());
	}
}

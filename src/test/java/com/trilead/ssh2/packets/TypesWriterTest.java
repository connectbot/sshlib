package com.trilead.ssh2.packets;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import org.junit.Test;

/**
 * Tests for TypesWriter - SSH protocol binary data serialization.
 * Ensures correct encoding of various data types used in SSH packets.
 */
public class TypesWriterTest {

	@Test
	public void testConstructorInitialization() {
		TypesWriter tw = new TypesWriter();

		assertEquals("Initial length should be 0", 0, tw.length());
		assertArrayEquals("Initial bytes should be empty", new byte[0], tw.getBytes());
	}

	@Test
	public void testWriteByteSimple() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0x42);

		assertEquals("Length should be 1", 1, tw.length());
		assertArrayEquals("Byte should be written correctly", new byte[] {0x42}, tw.getBytes());
	}

	@Test
	public void testWriteByteMultiple() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0x01);
		tw.writeByte(0x02);
		tw.writeByte(0xFF);

		assertEquals("Length should be 3", 3, tw.length());
		assertArrayEquals(
				"Bytes should be written in order",
				new byte[] {0x01, 0x02, (byte) 0xFF},
				tw.getBytes());
	}

	@Test
	public void testWriteByteWithOffset() {
		TypesWriter tw = new TypesWriter();
		// First establish position by writing normally
		tw.writeByte(0x00);
		tw.writeByte(0x00);

		// Now overwrite using offset
		tw.writeByte(0x10, 0); // Write at offset 0
		tw.writeByte(0x20, 1); // Write at offset 1

		byte[] bytes = tw.getBytes();
		assertEquals("First byte should be 0x10", 0x10, bytes[0]);
		assertEquals("Second byte should be 0x20", 0x20, bytes[1]);
	}

	@Test
	public void testWriteBooleanTrue() {
		TypesWriter tw = new TypesWriter();
		tw.writeBoolean(true);

		assertEquals("Length should be 1", 1, tw.length());
		assertArrayEquals("True should be encoded as 1", new byte[] {0x01}, tw.getBytes());
	}

	@Test
	public void testWriteBooleanFalse() {
		TypesWriter tw = new TypesWriter();
		tw.writeBoolean(false);

		assertEquals("Length should be 1", 1, tw.length());
		assertArrayEquals("False should be encoded as 0", new byte[] {0x00}, tw.getBytes());
	}

	@Test
	public void testWriteUINT32Zero() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(0);

		assertEquals("Length should be 4", 4, tw.length());
		assertArrayEquals(
				"Zero should be encoded as 4 zero bytes",
				new byte[] {0x00, 0x00, 0x00, 0x00},
				tw.getBytes());
	}

	@Test
	public void testWriteUINT32One() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(1);

		assertEquals("Length should be 4", 4, tw.length());
		assertArrayEquals(
				"One should be big-endian encoded",
				new byte[] {0x00, 0x00, 0x00, 0x01},
				tw.getBytes());
	}

	@Test
	public void testWriteUINT32MaxValue() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(0xFFFFFFFF);

		assertEquals("Length should be 4", 4, tw.length());
		assertArrayEquals(
				"Max uint32 should be all 0xFF",
				new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
				tw.getBytes());
	}

	@Test
	public void testWriteUINT32MixedBytes() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(0x12345678);

		assertEquals("Length should be 4", 4, tw.length());
		assertArrayEquals(
				"Should encode in big-endian order",
				new byte[] {0x12, 0x34, 0x56, 0x78},
				tw.getBytes());
	}

	@Test
	public void testWriteUINT32WithOffset() {
		TypesWriter tw = new TypesWriter();
		// First write something to establish the buffer size
		tw.writeUINT32(0x00000000);

		// Now overwrite at offset 0
		tw.writeUINT32(0xAABBCCDD, 0);

		byte[] bytes = tw.getBytes();
		assertArrayEquals(
				"Should write at specified offset",
				new byte[] {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD},
				bytes);
	}

	@Test
	public void testWriteUINT64Zero() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT64(0L);

		assertEquals("Length should be 8", 8, tw.length());
		assertArrayEquals(
				"Zero should be 8 zero bytes",
				new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				tw.getBytes());
	}

	@Test
	public void testWriteUINT64One() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT64(1L);

		assertEquals("Length should be 8", 8, tw.length());
		assertArrayEquals(
				"One should be big-endian encoded",
				new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				tw.getBytes());
	}

	@Test
	public void testWriteUINT64MaxValue() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT64(0xFFFFFFFFFFFFFFFFL);

		assertEquals("Length should be 8", 8, tw.length());
		assertArrayEquals(
				"Max uint64 should be all 0xFF",
				new byte[] {
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF
				},
				tw.getBytes());
	}

	@Test
	public void testWriteUINT64MixedBytes() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT64(0x0123456789ABCDEFL);

		assertEquals("Length should be 8", 8, tw.length());
		assertArrayEquals(
				"Should encode in big-endian order",
				new byte[] {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF},
				tw.getBytes());
	}

	@Test
	public void testWriteBytesSimple() {
		TypesWriter tw = new TypesWriter();
		byte[] data = {0x01, 0x02, 0x03};
		tw.writeBytes(data);

		assertEquals("Length should match input", 3, tw.length());
		assertArrayEquals("Bytes should be copied", data, tw.getBytes());
	}

	@Test
	public void testWriteBytesEmpty() {
		TypesWriter tw = new TypesWriter();
		tw.writeBytes(new byte[0]);

		assertEquals("Length should be 0", 0, tw.length());
		assertArrayEquals("Should remain empty", new byte[0], tw.getBytes());
	}

	@Test
	public void testWriteBytesWithOffsetAndLength() {
		TypesWriter tw = new TypesWriter();
		byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05};
		tw.writeBytes(data, 1, 3); // Write bytes at index 1, 2, 3

		assertEquals("Length should be 3", 3, tw.length());
		assertArrayEquals(
				"Should write specified range",
				new byte[] {0x02, 0x03, 0x04},
				tw.getBytes());
	}

	@Test
	public void testWriteStringSimple() {
		TypesWriter tw = new TypesWriter();
		tw.writeString("test");

		// String format: 4 bytes length + content
		assertEquals("Length should be 4 + 4", 8, tw.length());

		byte[] result = tw.getBytes();
		// First 4 bytes are length (4 in big-endian)
		assertEquals("Length prefix should be 4", 4, (result[3] & 0xFF));
		// Next 4 bytes are 'test'
		assertEquals("First char should be 't'", 't', (char) result[4]);
		assertEquals("Second char should be 'e'", 'e', (char) result[5]);
	}

	@Test
	public void testWriteStringEmpty() {
		TypesWriter tw = new TypesWriter();
		tw.writeString("");

		assertEquals("Length should be 4 (just the length prefix)", 4, tw.length());
		assertArrayEquals(
				"Empty string should have zero length",
				new byte[] {0x00, 0x00, 0x00, 0x00},
				tw.getBytes());
	}

	@Test
	public void testWriteStringWithCharset() throws UnsupportedEncodingException {
		TypesWriter tw = new TypesWriter();
		tw.writeString("test", "UTF-8");

		assertEquals("Length should be 4 + 4", 8, tw.length());
		byte[] result = tw.getBytes();
		assertEquals("Length prefix should be 4", 4, (result[3] & 0xFF));
	}

	@Test
	public void testWriteStringWithNullCharset() throws UnsupportedEncodingException {
		TypesWriter tw = new TypesWriter();
		tw.writeString("test", null);

		// Should use default charset
		assertEquals("Should write string with default charset", 8, tw.length());
	}

	@Test
	public void testWriteStringBytesDirectly() {
		TypesWriter tw = new TypesWriter();
		byte[] data = {0x41, 0x42, 0x43}; // "ABC"
		tw.writeString(data, 0, 3);

		assertEquals("Length should be 4 + 3", 7, tw.length());

		byte[] result = tw.getBytes();
		// First 4 bytes: length = 3
		assertEquals("Length should be 3", 3, (result[3] & 0xFF));
		// Next 3 bytes: data
		assertEquals("First byte should be 0x41", 0x41, result[4]);
		assertEquals("Second byte should be 0x42", 0x42, result[5]);
		assertEquals("Third byte should be 0x43", 0x43, result[6]);
	}

	@Test
	public void testWriteNameListEmpty() {
		TypesWriter tw = new TypesWriter();
		tw.writeNameList(new String[0]);

		assertEquals("Empty name list should have 4-byte length", 4, tw.length());
		assertArrayEquals(
				"Empty list should be zero-length string",
				new byte[] {0x00, 0x00, 0x00, 0x00},
				tw.getBytes());
	}

	@Test
	public void testWriteNameListSingle() {
		TypesWriter tw = new TypesWriter();
		tw.writeNameList(new String[] {"ssh-rsa"});

		byte[] result = tw.getBytes();
		// Length prefix (4 bytes) + "ssh-rsa" (7 bytes) = 11
		assertEquals("Length should be 11", 11, tw.length());

		// Verify length prefix is 7
		assertEquals("Length prefix should be 7", 7, (result[3] & 0xFF));
	}

	@Test
	public void testWriteNameListMultiple() {
		TypesWriter tw = new TypesWriter();
		tw.writeNameList(new String[] {"ssh-rsa", "ssh-dss"});

		byte[] result = tw.getBytes();
		// Length prefix (4 bytes) + "ssh-rsa,ssh-dss" (15 bytes) = 19
		assertEquals("Length should be 19", 19, tw.length());

		// Verify length prefix is 15
		assertEquals("Length prefix should be 15", 15, (result[3] & 0xFF));

		// Verify comma separator exists
		String content = new String(result, 4, result.length - 4);
		assertEquals("Content should be comma-separated", "ssh-rsa,ssh-dss", content);
	}

	@Test
	public void testWriteMPIntZero() {
		TypesWriter tw = new TypesWriter();
		tw.writeMPInt(BigInteger.ZERO);

		assertEquals("Zero should be encoded as 4-byte zero length", 4, tw.length());
		assertArrayEquals(
				"Zero mpint is zero-length string",
				new byte[] {0x00, 0x00, 0x00, 0x00},
				tw.getBytes());
	}

	@Test
	public void testWriteMPIntPositive() {
		TypesWriter tw = new TypesWriter();
		tw.writeMPInt(BigInteger.valueOf(0x1234));

		byte[] result = tw.getBytes();
		// Length will be 4 bytes + the bigint bytes
		// 0x1234 = 2 bytes, so total = 6
		assertEquals("Should have length prefix + data", 6, tw.length());

		// Verify length prefix
		assertEquals("Length prefix should be 2", 2, (result[3] & 0xFF));
	}

	@Test
	public void testWriteMPIntNegative() {
		TypesWriter tw = new TypesWriter();
		tw.writeMPInt(BigInteger.valueOf(-1));

		// Negative numbers are encoded with sign bit
		byte[] result = tw.getBytes();
		// Should have length prefix + signed representation
		assertEquals("Negative mpint should have length prefix", true, tw.length() > 4);
	}

	@Test
	public void testMultipleWrites() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0x01);
		tw.writeBoolean(true);
		tw.writeUINT32(0x12345678);
		tw.writeByte(0xFF);

		// 1 byte + 1 byte + 4 bytes + 1 byte = 7 bytes
		assertEquals("Total length should be 7", 7, tw.length());

		byte[] result = tw.getBytes();
		assertEquals("First byte should be 0x01", 0x01, result[0]);
		assertEquals("Second byte should be true (0x01)", 0x01, result[1]);
		assertEquals("UINT32 first byte", 0x12, result[2]);
		assertEquals("Last byte should be 0xFF", (byte) 0xFF, result[6]);
	}

	@Test
	public void testBufferResize() {
		TypesWriter tw = new TypesWriter();

		// Write more than initial 256 bytes to trigger resize
		byte[] largeData = new byte[300];
		for (int i = 0; i < 300; i++) {
			largeData[i] = (byte) i;
		}

		tw.writeBytes(largeData);

		assertEquals("Length should be 300", 300, tw.length());
		byte[] result = tw.getBytes();
		assertEquals("Result should have 300 bytes", 300, result.length);

		// Verify data integrity after resize
		for (int i = 0; i < 300; i++) {
			assertEquals("Byte " + i + " should match", (byte) i, result[i]);
		}
	}

	@Test
	public void testGetBytesDoesNotModifyWriter() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(0x12345678);

		byte[] first = tw.getBytes();
		byte[] second = tw.getBytes();

		assertArrayEquals("Multiple getBytes() calls should return same data", first, second);
		assertEquals("Length should remain unchanged", 4, tw.length());
	}

	@Test
	public void testGetBytesWithDestinationArray() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0x01);
		tw.writeByte(0x02);
		tw.writeByte(0x03);

		byte[] dest = new byte[3];
		tw.getBytes(dest);

		assertArrayEquals(
				"Destination array should be filled",
				new byte[] {0x01, 0x02, 0x03},
				dest);
	}

	@Test
	public void testLengthTracking() {
		TypesWriter tw = new TypesWriter();

		assertEquals("Initial length should be 0", 0, tw.length());

		tw.writeByte(0x00);
		assertEquals("Length after 1 byte", 1, tw.length());

		tw.writeUINT32(0);
		assertEquals("Length after uint32", 5, tw.length());

		tw.writeUINT64(0L);
		assertEquals("Length after uint64", 13, tw.length());

		tw.writeBoolean(true);
		assertEquals("Length after boolean", 14, tw.length());
	}
}

package com.trilead.ssh2.packets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/**
 * Tests for TypesWriter - SSH protocol binary data serialization.
 * Ensures correct encoding of various data types used in SSH packets.
 */
public class TypesWriterTest {

	@Test
	public void testConstructorInitialization() {
		TypesWriter tw = new TypesWriter();

		assertEquals(0, tw.length(), "Initial length should be 0");
		assertArrayEquals(new byte[0], tw.getBytes(), "Initial bytes should be empty");
	}

	@Test
	public void testWriteByteSimple() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0x42);

		assertEquals(1, tw.length(), "Length should be 1");
		assertArrayEquals(new byte[] {0x42}, tw.getBytes(), "Byte should be written correctly");
	}

	@Test
	public void testWriteByteMultiple() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0x01);
		tw.writeByte(0x02);
		tw.writeByte(0xFF);

		assertEquals(3, tw.length(), "Length should be 3");
		assertArrayEquals(new byte[] {0x01, 0x02, (byte) 0xFF},
				tw.getBytes(), "Bytes should be written in order");
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
		assertEquals(0x10, bytes[0], "First byte should be 0x10");
		assertEquals(0x20, bytes[1], "Second byte should be 0x20");
	}

	@Test
	public void testWriteBooleanTrue() {
		TypesWriter tw = new TypesWriter();
		tw.writeBoolean(true);

		assertEquals(1, tw.length(), "Length should be 1");
		assertArrayEquals(new byte[] {0x01}, tw.getBytes(), "True should be encoded as 1");
	}

	@Test
	public void testWriteBooleanFalse() {
		TypesWriter tw = new TypesWriter();
		tw.writeBoolean(false);

		assertEquals(1, tw.length(), "Length should be 1");
		assertArrayEquals(new byte[] {0x00}, tw.getBytes(), "False should be encoded as 0");
	}

	@Test
	public void testWriteUINT32Zero() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(0);

		assertEquals(4, tw.length(), "Length should be 4");
		assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00},
				tw.getBytes(), "Zero should be encoded as 4 zero bytes");
	}

	@Test
	public void testWriteUINT32One() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(1);

		assertEquals(4, tw.length(), "Length should be 4");
		assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x01},
				tw.getBytes(), "One should be big-endian encoded");
	}

	@Test
	public void testWriteUINT32MaxValue() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(0xFFFFFFFF);

		assertEquals(4, tw.length(), "Length should be 4");
		assertArrayEquals(new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF},
				tw.getBytes(), "Max uint32 should be all 0xFF");
	}

	@Test
	public void testWriteUINT32MixedBytes() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(0x12345678);

		assertEquals(4, tw.length(), "Length should be 4");
		assertArrayEquals(new byte[] {0x12, 0x34, 0x56, 0x78},
				tw.getBytes(), "Should encode in big-endian order");
	}

	@Test
	public void testWriteUINT32WithOffset() {
		TypesWriter tw = new TypesWriter();
		// First write something to establish the buffer size
		tw.writeUINT32(0x00000000);

		// Now overwrite at offset 0
		tw.writeUINT32(0xAABBCCDD, 0);

		byte[] bytes = tw.getBytes();
		assertArrayEquals(new byte[] {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD},
				bytes, "Should write at specified offset");
	}

	@Test
	public void testWriteUINT64Zero() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT64(0L);

		assertEquals(8, tw.length(), "Length should be 8");
		assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				tw.getBytes(), "Zero should be 8 zero bytes");
	}

	@Test
	public void testWriteUINT64One() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT64(1L);

		assertEquals(8, tw.length(), "Length should be 8");
		assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				tw.getBytes(), "One should be big-endian encoded");
	}

	@Test
	public void testWriteUINT64MaxValue() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT64(0xFFFFFFFFFFFFFFFFL);

		assertEquals(8, tw.length(), "Length should be 8");
		assertArrayEquals(new byte[] {
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF,
					(byte) 0xFF
				},
				tw.getBytes(), "Max uint64 should be all 0xFF");
	}

	@Test
	public void testWriteUINT64MixedBytes() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT64(0x0123456789ABCDEFL);

		assertEquals(8, tw.length(), "Length should be 8");
		assertArrayEquals(new byte[] {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF},
				tw.getBytes(), "Should encode in big-endian order");
	}

	@Test
	public void testWriteBytesSimple() {
		TypesWriter tw = new TypesWriter();
		byte[] data = {0x01, 0x02, 0x03};
		tw.writeBytes(data);

		assertEquals(3, tw.length(), "Length should match input");
		assertArrayEquals(data, tw.getBytes(), "Bytes should be copied");
	}

	@Test
	public void testWriteBytesEmpty() {
		TypesWriter tw = new TypesWriter();
		tw.writeBytes(new byte[0]);

		assertEquals(0, tw.length(), "Length should be 0");
		assertArrayEquals(new byte[0], tw.getBytes(), "Should remain empty");
	}

	@Test
	public void testWriteBytesWithOffsetAndLength() {
		TypesWriter tw = new TypesWriter();
		byte[] data = {0x01, 0x02, 0x03, 0x04, 0x05};
		tw.writeBytes(data, 1, 3); // Write bytes at index 1, 2, 3

		assertEquals(3, tw.length(), "Length should be 3");
		assertArrayEquals(new byte[] {0x02, 0x03, 0x04},
				tw.getBytes(), "Should write specified range");
	}

	@Test
	public void testWriteStringSimple() {
		TypesWriter tw = new TypesWriter();
		tw.writeString("test");

		// String format: 4 bytes length + content
		assertEquals(8, tw.length(), "Length should be 4 + 4");

		byte[] result = tw.getBytes();
		// First 4 bytes are length (4 in big-endian)
		assertEquals(4, (result[3] & 0xFF), "Length prefix should be 4");
		// Next 4 bytes are 'test'
		assertEquals('t', (char) result[4], "First char should be 't'");
		assertEquals('e', (char) result[5], "Second char should be 'e'");
	}

	@Test
	public void testWriteStringEmpty() {
		TypesWriter tw = new TypesWriter();
		tw.writeString("");

		assertEquals(4, tw.length(), "Length should be 4 (just the length prefix)");
		assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00},
				tw.getBytes(), "Empty string should have zero length");
	}

	@Test
	public void testWriteStringWithCharset() throws UnsupportedEncodingException {
		TypesWriter tw = new TypesWriter();
		tw.writeString("test", "UTF-8");

		assertEquals(8, tw.length(), "Length should be 4 + 4");
		byte[] result = tw.getBytes();
		assertEquals(4, (result[3] & 0xFF), "Length prefix should be 4");
	}

	@Test
	public void testWriteStringWithNullCharset() throws UnsupportedEncodingException {
		TypesWriter tw = new TypesWriter();
		tw.writeString("test", null);

		// Should use default charset
		assertEquals(8, tw.length(), "Should write string with default charset");
	}

	@Test
	public void testWriteStringBytesDirectly() {
		TypesWriter tw = new TypesWriter();
		byte[] data = {0x41, 0x42, 0x43}; // "ABC"
		tw.writeString(data, 0, 3);

		assertEquals(7, tw.length(), "Length should be 4 + 3");

		byte[] result = tw.getBytes();
		// First 4 bytes: length = 3
		assertEquals(3, (result[3] & 0xFF), "Length should be 3");
		// Next 3 bytes: data
		assertEquals(0x41, result[4], "First byte should be 0x41");
		assertEquals(0x42, result[5], "Second byte should be 0x42");
		assertEquals(0x43, result[6], "Third byte should be 0x43");
	}

	@Test
	public void testWriteNameListEmpty() {
		TypesWriter tw = new TypesWriter();
		tw.writeNameList(new String[0]);

		assertEquals(4, tw.length(), "Empty name list should have 4-byte length");
		assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00},
				tw.getBytes(), "Empty list should be zero-length string");
	}

	@Test
	public void testWriteNameListSingle() {
		TypesWriter tw = new TypesWriter();
		tw.writeNameList(new String[] {"ssh-rsa"});

		byte[] result = tw.getBytes();
		// Length prefix (4 bytes) + "ssh-rsa" (7 bytes) = 11
		assertEquals(11, tw.length(), "Length should be 11");

		// Verify length prefix is 7
		assertEquals(7, (result[3] & 0xFF), "Length prefix should be 7");
	}

	@Test
	public void testWriteNameListMultiple() {
		TypesWriter tw = new TypesWriter();
		tw.writeNameList(new String[] {"ssh-rsa", "ssh-dss"});

		byte[] result = tw.getBytes();
		// Length prefix (4 bytes) + "ssh-rsa,ssh-dss" (15 bytes) = 19
		assertEquals(19, tw.length(), "Length should be 19");

		// Verify length prefix is 15
		assertEquals(15, (result[3] & 0xFF), "Length prefix should be 15");

		// Verify comma separator exists
		String content = new String(result, 4, result.length - 4);
		assertEquals("ssh-rsa,ssh-dss", content, "Content should be comma-separated");
	}

	@Test
	public void testWriteMPIntZero() {
		TypesWriter tw = new TypesWriter();
		tw.writeMPInt(BigInteger.ZERO);

		assertEquals(4, tw.length(), "Zero should be encoded as 4-byte zero length");
		assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x00},
				tw.getBytes(), "Zero mpint is zero-length string");
	}

	@Test
	public void testWriteMPIntPositive() {
		TypesWriter tw = new TypesWriter();
		tw.writeMPInt(BigInteger.valueOf(0x1234));

		byte[] result = tw.getBytes();
		// Length will be 4 bytes + the bigint bytes
		// 0x1234 = 2 bytes, so total = 6
		assertEquals(6, tw.length(), "Should have length prefix + data");

		// Verify length prefix
		assertEquals(2, (result[3] & 0xFF), "Length prefix should be 2");
	}

	@Test
	public void testWriteMPIntNegative() {
		TypesWriter tw = new TypesWriter();
		tw.writeMPInt(BigInteger.valueOf(-1));

		// Negative numbers are encoded with sign bit
		byte[] result = tw.getBytes();
		// Should have length prefix + signed representation
		assertEquals(true, tw.length() > 4, "Negative mpint should have length prefix");
	}

	@Test
	public void testMultipleWrites() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0x01);
		tw.writeBoolean(true);
		tw.writeUINT32(0x12345678);
		tw.writeByte(0xFF);

		// 1 byte + 1 byte + 4 bytes + 1 byte = 7 bytes
		assertEquals(7, tw.length(), "Total length should be 7");

		byte[] result = tw.getBytes();
		assertEquals(0x01, result[0], "First byte should be 0x01");
		assertEquals(0x01, result[1], "Second byte should be true (0x01)");
		assertEquals(0x12, result[2], "UINT32 first byte");
		assertEquals((byte) 0xFF, result[6], "Last byte should be 0xFF");
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

		assertEquals(300, tw.length(), "Length should be 300");
		byte[] result = tw.getBytes();
		assertEquals(300, result.length, "Result should have 300 bytes");

		// Verify data integrity after resize
		for (int i = 0; i < 300; i++) {
			assertEquals((byte) i, result[i], "Byte " + i + " should match");
		}
	}

	@Test
	public void testGetBytesDoesNotModifyWriter() {
		TypesWriter tw = new TypesWriter();
		tw.writeUINT32(0x12345678);

		byte[] first = tw.getBytes();
		byte[] second = tw.getBytes();

		assertArrayEquals(first, second, "Multiple getBytes() calls should return same data");
		assertEquals(4, tw.length(), "Length should remain unchanged");
	}

	@Test
	public void testGetBytesWithDestinationArray() {
		TypesWriter tw = new TypesWriter();
		tw.writeByte(0x01);
		tw.writeByte(0x02);
		tw.writeByte(0x03);

		byte[] dest = new byte[3];
		tw.getBytes(dest);

		assertArrayEquals(new byte[] {0x01, 0x02, 0x03},
				dest, "Destination array should be filled");
	}

	@Test
	public void testLengthTracking() {
		TypesWriter tw = new TypesWriter();

		assertEquals(0, tw.length(), "Initial length should be 0");

		tw.writeByte(0x00);
		assertEquals(1, tw.length(), "Length after 1 byte");

		tw.writeUINT32(0);
		assertEquals(5, tw.length(), "Length after uint32");

		tw.writeUINT64(0L);
		assertEquals(13, tw.length(), "Length after uint64");

		tw.writeBoolean(true);
		assertEquals(14, tw.length(), "Length after boolean");
	}
}

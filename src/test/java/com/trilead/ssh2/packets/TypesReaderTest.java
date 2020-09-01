package com.trilead.ssh2.packets;

import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.emptyArray;
import static org.hamcrest.Matchers.equalTo;

public class TypesReaderTest {
	public static TypesReader readerOf(int... ints) {
		byte[] bytes = new byte[ints.length];
		for (int i = 0; i < ints.length; i++) {
			bytes[i] = (byte) ints[i];
		}
		return new TypesReader(bytes);
	}

	@Test
	public void constructorArrayOffset_Success() throws Exception {
		TypesReader tr = new TypesReader(new byte[] { 0x01, 0x02, 0x03 }, 1);
		assertThat(tr.remain(), equalTo(2));
		assertThat(tr.readByte(), equalTo(0x02));
		assertThat(tr.remain(), equalTo(1));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayOffset_NegativeOffset_Failure() {
		new TypesReader(new byte[] { 0x01, 0x02, 0x03 }, -1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayOffset_OffsetBeyondEnd_Failure() {
		new TypesReader(new byte[] { 0x01, 0x02, 0x03 }, 4);
	}

	@Test
	public void constructorArrayOffsetLength_Success() throws Exception {
		TypesReader tr = new TypesReader(
			new byte[] { 0x01, 0x02, 0x03 }, 2, 1);
		assertThat(tr.remain(), equalTo(1));
		assertThat(tr.readByte(), equalTo(0x03));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayOffsetLength_OffsetBeyondEnd_Failure() {
		new TypesReader(new byte[] { 0x01, 0x02, 0x03 }, 3, 1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayOffsetLength_NegativeOffset_Failure() {
		new TypesReader(new byte[] { 0x01, 0x02, 0x03 }, -1, 1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayOffsetLength_PositionPastEnd_Failure() {
		new TypesReader(new byte[] { 0x01, 0x02, 0x03 }, 3, 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayOffsetLength_NegativeOffsetLengthTooLong_Failure() {
		new TypesReader(new byte[] { 0x01, 0x02, 0x03 }, -1, 4);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayOffsetLength_LengthTooLong_Failure() {
		new TypesReader(new byte[] { 0x01, 0x02, 0x03 }, 0, 4);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayOffsetLength_NegativeLength_Failure() {
		new TypesReader(new byte[] { 0x01, 0x02, 0x03 }, 0, -1);
	}

	@Test
	public void readByte_SingleByte_Success() throws IOException {
		assertThat(readerOf((byte) 0x01).readByte(), equalTo(0x01));
	}

	@Test(expected = IOException.class)
	public void readByte_ReadBeyondEnd_Failure() throws IOException {
		TypesReader tr = readerOf(0xaa);
		assertThat(tr.readByte(), equalTo(0xaa));
		assertThat(tr.readByte(), equalTo(0x55));
		tr.readByte();
	}

	@Test(expected = IOException.class)
	public void readByte_PacketTooShort_Failure() throws Exception {
		readerOf().readByte();
	}

	@Test
	public void readBytes_ZeroLength_Success() throws Exception {
		assertThat(
			readerOf().readBytes(0),
			equalTo(new byte[0]));
	}

	@Test
	public void readByteString_ZeroBytes_Success() throws Exception {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x00).readByteString(),
			equalTo(new byte[0]));
	}

	@Test
	public void readByteString_SingleByte_Success() throws Exception {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x01, 0x05).readByteString(),
			equalTo(new byte[] { 0x05 }));
	}

	@Test
	public void readByteString_FiveBytes_Success() throws Exception {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x05, 0x01, 0x50, 0x11, (byte) 0xff, 0x00).readByteString(),
			equalTo(new byte[] { 0x01, 0x50, 0x11, (byte) 0xff, 0x00 }));
	}

	@Test(expected = IOException.class)
	public void readByteString_PacketTooShort_Failure() throws Exception {
		readerOf().readByteString();
	}


	@Test(expected = IOException.class)
	public void readByteString_LengthTooLong_Failure() throws Exception {
		readerOf(0x00, 0x00, 0x00, 0x02, 0x01).readByteString();
	}


	@Test
	public void readBytes_SingleByte_Success() throws Exception {
		assertThat(
			readerOf(0xaa).readBytes(1),
			equalTo(new byte[] { (byte) 0xaa }));
	}

	@Test
	public void readBytes_FiveBytes_Success() throws Exception {
		assertThat(
			readerOf(0x01, 0x50, 0x11, (byte) 0xff, 0x00).readBytes(5),
			equalTo(new byte[] { 0x01, 0x50, 0x11, (byte) 0xff, 0x00 }));
	}

	@Test(expected = IOException.class)
	public void readBytes_PacketTooShort_Failure() throws Exception {
		readerOf().readBytes(1);
	}

	@Test(expected = IOException.class)
	public void readBytes_NegativeLength_Failure() throws Exception {
		readerOf(0x01, 0x02).readBytes(-1);
	}

	@Test(expected = IOException.class)
	public void readBytes_NegativeLength_OffsetIntoArray_Failure() throws Exception {
		TypesReader tr = readerOf(0x01, 0x02);
		tr.readByte();
		tr.readBytes(-1);
	}

	@Test
	public void readBytes_BII_ZeroLength_Success() throws Exception {
		readerOf().readBytes(new byte[0], 0, 0);
	}

	@Test
	public void readBytes_BII_SingleByte_Success() throws Exception {
		byte[] output = new byte[3];
		readerOf(0x19).readBytes(output, 1, 1);
		assertThat(output,
			equalTo(new byte[] { 0x00, (byte) 0x19, 0x00}));
	}

	@Test
	public void readBytes_BII_FiveBytes_Success() throws Exception {
		byte[] output = new byte[5];
		readerOf(0x19, 0x00, 0xFF, 0xAA, 0x5a).readBytes(output, 0, 5);
		assertThat(
			output,
			equalTo(new byte[] { 0x19, 0x00, (byte) 0xFF, (byte) 0xAA, 0x5a }));
	}

	@Test(expected = IOException.class)
	public void readBytes_BII_PacketTooShort_Failure() throws Exception {
		readerOf().readBytes(new byte[12], 0, 1);
	};

	@Test(expected = IOException.class)
	public void readBytes_BII_NegativeOFFSET_Failure() throws Exception {
		readerOf(0x01, 0x02).readBytes(new byte[5], -1, 1);
	}

	@Test(expected = IOException.class)
	public void readBytes_BII_NegativeLength_Failure() throws Exception {
		readerOf(0x01, 0x02).readBytes(new byte[5], 0, -1);
	}

	@Test(expected = IOException.class)
	public void readBytes_BII_NegativeOffset_OffsetIntoArray_Failure() throws Exception {
		TypesReader tr = readerOf(0x01, 0x02, 0x03);
		tr.readByte();
		byte[] output = new byte[5];
		tr.readBytes(output, -1, 1);
	}

	@Test(expected = IOException.class)
	public void readBytes_BII_NegativeLength_OffsetIntoArray_Failure() throws Exception {
		TypesReader tr = readerOf(0x01, 0x02);
		tr.readByte();
		byte[] output = new byte[5];
		tr.readBytes(output, 1, -1);
	}

	@Test(expected = IOException.class)
	public void readBytes_BII_TooFarIntoOutputBuffer_Failure() throws Exception {
		readerOf(0x01, 0x02, 0x03, 0x04).readBytes(new byte[1], 1, 1);
	}

	@Test(expected = IOException.class)
	public void readBytes_BII_TooLongForOutputBuffer_Failure() throws Exception {
		readerOf(0x01, 0x02, 0x03, 0x04).readBytes(new byte[1], 0, 2);
	}

	@Test(expected = IOException.class)
	public void readBoolean_PacketTooShort_Failure() throws Exception {
		readerOf().readBoolean();
	}

	@Test
	public void readBoolean_True_Success() throws Exception {
		assertThat(
			readerOf(0x01).readBoolean(),
			equalTo(true));
	}

	@Test
	public void readBoolean_False_Success() throws Exception {
		assertThat(
			readerOf(0x00).readBoolean(),
			equalTo(false));
	}

	@Test
	public void readBoolean_OtherValuesAreTrue_Success() throws Exception {
		for (int i = 2; i < 256; i++) {
			assertThat(
				readerOf(i).readBoolean(),
				equalTo(true));
		}
	}

	@Test
	public void readUINT32_Zero_Success() throws Exception {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x00).readUINT32(),
			equalTo(0));
	}

	@Test
	public void readUINT32_KAT1_Success() throws Exception {
		assertThat(
			readerOf(0x29, 0xb7, 0xf4, 0xaa).readUINT32(),
			equalTo(699921578));
	}

	@Test(expected = IOException.class)
	public void readUINT32_PacketTooShort_Failure() throws Exception {
		readerOf(0x00, 0x01, 0x02).readUINT32();
	}

	@Test
	public void readUINT64_Success() throws Exception {
		assertThat(
			readerOf(0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00).readUINT64(),
			equalTo(72057594037927936L));
	}

	@Test(expected = IOException.class)
	public void readUINT64_PacketTooShort_Failure() throws Exception {
		readerOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06).readUINT64();
	}

	@Test
	public void readMPINT_KAT1_Success() throws IOException {
		assertThat(readerOf(0x00, 0x00, 0x00, 0x00).readMPINT(),
			equalTo(BigInteger.ZERO));
	}

	@Test
	public void readMPINT_KAT2_Success() throws IOException {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7).readMPINT(),
			equalTo(new BigInteger("9a378f9b2e332a7", 16)));
	}

	@Test
	public void readMPINT_KAT3_Success() throws IOException {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x02, 0x00, 0x80).readMPINT(),
			equalTo(BigInteger.valueOf(0x80)));
	}

	@Test
	public void readMPINT_KAT4_Success() throws IOException {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x02, 0xed, 0xcc).readMPINT(),
			equalTo(BigInteger.valueOf(-0x1234)));
	}

	@Test
	public void readMPINT_KAT5_Success() throws IOException {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x05, 0xff, 0x21, 0x52, 0x41, 0x11).readMPINT(),
			equalTo(new BigInteger("-deadbeef", 16)));
	}

	@Test
	public void readString_UTF8Charset_Success() throws Exception {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g').readString("UTF-8"),
			equalTo("testing"));
	}

	@Test
	public void readString_NullCharset_Success() throws Exception {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g').readString(null),
			equalTo("testing"));
	}

	@Test(expected = IOException.class)
	public void readString_InputLengthTooShort_Failure() throws Exception {
		readerOf(0x00, 0x00, 0x00).readString("UTF-8");
	}

	@Test(expected = IOException.class)
	public void readString_InputTooShort_Failure() throws Exception {
		readerOf(0x00, 0x00, 0x00, 0x02, 't').readString("UTF-8");
	}

	@Test
	public void readString_KAT1_Success() throws Exception {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g').readString(),
			equalTo("testing"));
	}

	@Test(expected = IOException.class)
	public void readString_PacketTooShort_Failure() throws Exception {
		readerOf(0x00, 0x00, 0x00, 0x07).readString();
	}

	@Test(expected = IOException.class)
	public void readNameList_LengthUnavailable_Failure() throws IOException {
		readerOf(0x00, 0x00, 0x03).readNameList();
	}

	@Test(expected = IOException.class)
	public void readNameList_ArrayTooShort_Failure() throws IOException {
		readerOf(0x00, 0x00, 0x00, 0x01).readNameList();
	}

	@Test
	public void readNameList_KAT1_Success() throws IOException {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x00).readNameList(),
			emptyArray());
	}

	@Test
	public void readNameList_KAT2_Success() throws IOException {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x04, 0x7a, 0x6c, 0x69, 0x62).readNameList(),
			arrayContaining("zlib"));
	}

	@Test
	public void readNameList_KAT3_Success() throws IOException {
		assertThat(
			readerOf(0x00, 0x00, 0x00, 0x09, 0x7a, 0x6c, 0x69,
				0x62, 0x2c, 0x6e, 0x6f, 0x6e, 0x65).readNameList(),
			arrayContaining("zlib", "none"));
	}
}

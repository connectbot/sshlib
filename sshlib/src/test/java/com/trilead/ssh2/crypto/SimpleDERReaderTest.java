package com.trilead.ssh2.crypto;

import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

/**
 * Created by kenny on 12/25/15.
 */
public class SimpleDERReaderTest {
    @Test
    public void readLength_Extended_OverlyLongLength() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x85, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        assertEquals(-1, reader.readLength());
    }

    @Test
    public void readLength_Extended_TooLongForInt() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        assertEquals(-1, reader.readLength());
    }

    @Test
    public void readLength_Extended_Zero() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x80, (byte) 0x01
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        assertEquals(-1, reader.readLength());
    }

    @Test
    public void readLength_Extended_Valid() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x82, (byte) 0x05, (byte) 0xFF
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        assertEquals(0x5FF, reader.readLength());
    }

    @Test
    public void readLength_Short_Zero() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x00
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        assertEquals(0, reader.readLength());
    }

    @Test
    public void readLength_Short_Regular() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x09
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        assertEquals(9, reader.readLength());
    }

    @Test
    public void readInt_MaxInt() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x02, (byte) 0x04, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        assertEquals(BigInteger.valueOf(0xFFFFFFFF), reader.readInt());
    }

    @Test
    public void readInt_NotReallyInteger() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x01, (byte) 0x04, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        try {
            reader.readInt();
        } catch (IOException expected) {
            assertThat(expected.getMessage(), containsString("Expected DER Integer"));
        }
    }

    @Test
    public void readInt_InvalidLength() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x02, (byte) 0x80, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        try {
            reader.readInt();
        } catch (IOException expected) {
            assertThat(expected.getMessage(), containsString("Illegal len"));
        }
    }

    @Test
    public void readInt_ShortArray() throws Exception {
        byte[] vector = new byte[] {
                (byte) 0x02, (byte) 0x02, (byte) 0xFF
        };
        SimpleDERReader reader = new SimpleDERReader(vector);
        try {
            reader.readInt();
        } catch (IOException expected) {
        }
    }
}
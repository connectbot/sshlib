package com.trilead.ssh2.crypto;

import org.junit.Test;

import java.io.IOException;

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
}
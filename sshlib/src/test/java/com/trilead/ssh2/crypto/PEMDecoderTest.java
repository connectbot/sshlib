package com.trilead.ssh2.crypto;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyPair;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * @author Michael Clarke
 */
public class PEMDecoderTest {

    @Test
    public void testRsaKeyDecodingTest() throws IOException {
        KeyPair expected = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("rsa-private-key.txt")), null);
        KeyPair actual = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("rsa-openssh2-private-key.txt")), "password");

        assertEquals(expected.getPrivate(), actual.getPrivate());
        assertEquals(expected.getPublic(), actual.getPublic());
    }

    @Test
    public void testDsaKeyDecodingTest() throws IOException {
        KeyPair oldFormat = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("dsa-private-key.txt")), null);
        KeyPair newFormat = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("dsa-openssh2-private-key.txt")), null);

        assertEquals(oldFormat.getPublic(), newFormat.getPublic());
        assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
    }

    @Test
    public void testEcdsaNistp256KeyDecodingTest() throws IOException {
        KeyPair oldFormat = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("ecdsa-nistp256-private-key.txt")), null);
        KeyPair newFormat = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("ecdsa-nistp256-openssh2-private-key.txt")), null);

        assertEquals(oldFormat.getPublic(), newFormat.getPublic());
        assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
    }

    @Test
    public void testEcdsaNistp384KeyDecodingTest() throws IOException {
        KeyPair oldFormat = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("ecdsa-nistp384-private-key.txt")), null);
        KeyPair newFormat = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("ecdsa-nistp384-openssh2-private-key.txt")), null);

        assertEquals(oldFormat.getPublic(), newFormat.getPublic());
        assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
    }

    @Test
    public void testEcdsaNistp521KeyDecodingTest() throws IOException {
        KeyPair oldFormat = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("ecdsa-nistp521-private-key.txt")), null);
        KeyPair newFormat = PEMDecoder.decode(IOUtils.toCharArray(getClass().getResourceAsStream("ecdsa-nistp521-openssh2-private-key.txt")), null);

        assertEquals(oldFormat.getPublic(), newFormat.getPublic());
        assertEquals(oldFormat.getPrivate(), newFormat.getPrivate());
    }
}

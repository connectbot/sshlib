package com.trilead.ssh2.compression;

import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CompressionFactoryTest {
	@Test
	public void getDefaultCompressors_Success() {
		assertTrue(CompressionFactory.getDefaultCompressorList().length > 0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void brokenCompressor_Failure() {
		CompressionFactory.addCompressor("fake", "class.fake");
		CompressionFactory.createCompressor("fake");
	}

	@Test
	public void noneCompressorCreatesNull_Success() {
		assertNull(CompressionFactory.createCompressor("none"));
	}

	@Test
	public void realCompressor_Success() {
		assertNotNull(CompressionFactory.createCompressor("zlib"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidCompressor_Failure() {
		CompressionFactory.checkCompressorList(Collections.singletonList("broken").toArray(new String[1]));
	}
}

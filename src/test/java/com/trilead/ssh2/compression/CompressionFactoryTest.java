package com.trilead.ssh2.compression;

import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CompressionFactoryTest {
	@Test
	public void getDefaultCompressors_Success() {
		assertTrue(CompressionFactory.getDefaultCompressorList().length > 0);
	}

	@Test
	public void brokenCompressor_Failure() {
		assertThrows(IllegalArgumentException.class, () -> {
		CompressionFactory.addCompressor("fake", "class.fake");
		CompressionFactory.createCompressor("fake");
		});
	}

	@Test
	public void noneCompressorCreatesNull_Success() {
		assertNull(CompressionFactory.createCompressor("none"));
	}

	@Test
	public void realCompressor_Success() {
		assertNotNull(CompressionFactory.createCompressor("zlib"));
	}

	@Test
	public void invalidCompressor_Failure() {
		assertThrows(IllegalArgumentException.class, () -> {
		CompressionFactory.checkCompressorList(Collections.singletonList("broken").toArray(new String[1]));
		});
	}
}

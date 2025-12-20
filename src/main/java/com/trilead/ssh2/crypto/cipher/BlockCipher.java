package com.trilead.ssh2.crypto.cipher;

/**
 * BlockCipher.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: BlockCipher.java,v 1.1 2007/10/15 12:49:55 cplattne Exp $
 */
public interface BlockCipher
{
	void init(boolean forEncryption, byte[] key, byte[] iv) throws IllegalArgumentException;

	int getBlockSize();

	void transformBlock(byte[] src, int srcoff, byte[] dst, int dstoff);

	default void transformBlocks(byte[] src, int srcoff, byte[] dst, int dstoff, int numBlocks) {
		int blockSize = getBlockSize();
		for (int i = 0; i < numBlocks; i++) {
			transformBlock(src, srcoff + i * blockSize, dst, dstoff + i * blockSize);
		}
	}
}

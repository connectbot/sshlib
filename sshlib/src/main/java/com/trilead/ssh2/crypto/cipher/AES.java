
package com.trilead.ssh2.crypto.cipher;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * AES modes for SSH using the JCE.
 */
public abstract class AES implements BlockCipher
{
	private final int AES_BLOCK_SIZE = 16;

	protected Cipher cipher;

	@Override
	public void init(boolean forEncryption, byte[] key, byte[] iv) {
		try {
			cipher.init(forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
					new SecretKeySpec(key, "AES"),
					new IvParameterSpec(iv));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("Cannot initialize " + cipher.getAlgorithm(), e);
		}
	}

	@Override
	public int getBlockSize() {
		return AES_BLOCK_SIZE;
	}

	@Override
	public void transformBlock(byte[] src, int srcoff, byte[] dst, int dstoff) {
		try {
			cipher.update(src, srcoff, AES_BLOCK_SIZE, dst, dstoff);
		} catch (ShortBufferException e) {
			throw new AssertionError(e);
		}
	}

	public static class CBC extends AES {
		public CBC() throws IllegalArgumentException {
			try {
				cipher = Cipher.getInstance("AES/CBC/NoPadding");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new IllegalArgumentException("Cannot initialize AES/CBC/NoPadding", e);
			}
		}
	}

	public static class CTR extends AES {
		public CTR() throws IllegalArgumentException {
			try {
				cipher = Cipher.getInstance("AES/CTR/NoPadding");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new IllegalArgumentException("Cannot initialize AES/CBC/NoPadding", e);
			}
		}
	}
}

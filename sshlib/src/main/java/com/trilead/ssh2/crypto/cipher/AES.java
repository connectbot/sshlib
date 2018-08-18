
package com.trilead.ssh2.crypto.cipher;

/*
 This file was shamelessly taken from the Bouncy Castle Crypto package.
 Their licence file states the following:

 Copyright (c) 2000 - 2004 The Legion Of The Bouncy Castle
 (http://www.bouncycastle.org)

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE. 
 */

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

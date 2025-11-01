package com.trilead.ssh2.crypto.cipher;

import com.trilead.ssh2.crypto.digest.Poly1305;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * ChaCha20-Poly1305 AEAD cipher implementation for SSH.
 *
 * Implements the chacha20-poly1305@openssh.com cipher as specified in
 * draft-ietf-sshm-chacha20-poly1305-02.
 *
 * This implementation uses two separate ChaCha20 instances:
 * - K_1 (main_cipher): Encrypts packet payload, generates Poly1305 key
 * - K_2 (header_cipher): Encrypts packet length field
 *
 * The Poly1305 MAC is calculated over: encrypted_length || ciphertext
 * (NOT using standard AEAD AAD, per OpenSSH specification)
 *
 * This implementation is optimized to minimize garbage generation by reusing
 * cipher instances and temporary buffers across packets.
 *
 * @author Kenny Root
 */
public class ChaCha20Poly1305 implements AeadCipher
{
	public static final String SSH_NAME = "chacha20-poly1305@openssh.com";
	public static final int BLOCK_SIZE = 8;
	public static final int KEY_SIZE = 64;  // 2 x 32-byte keys
	public static final int TAG_SIZE = 16;  // Poly1305 tag

	private byte[] mainKey;     // K_1: first 32 bytes
	private byte[] headerKey;   // K_2: second 32 bytes

	// Reusable cipher instances to reduce garbage
	private Cipher headerCipher;
	private Cipher polyKeyCipher;
	private Cipher payloadCipher;
	private SecretKeySpec mainKeySpec;
	private SecretKeySpec headerKeySpec;

	// Reusable Poly1305 instance
	private final Poly1305 poly = new Poly1305();

	// Reusable buffers to reduce allocations
	private final byte[] nonce = new byte[12];
	private final byte[] polyKeyZeros = new byte[32];
	private final byte[] polyKey = new byte[32];
	private final byte[] computedTag = new byte[TAG_SIZE];
	private final byte[] skipToNextBlock = new byte[64];

	@Override
	public void init(boolean forEncryption, byte[] key, byte[] iv) throws IllegalArgumentException
	{
		if (key.length != KEY_SIZE)
		{
			throw new IllegalArgumentException("ChaCha20-Poly1305 requires 64 bytes of key material");
		}

		// Copy keys
		if (this.mainKey == null)
		{
			this.mainKey = new byte[32];
			this.headerKey = new byte[32];
		}
		System.arraycopy(key, 0, this.mainKey, 0, 32);
		System.arraycopy(key, 32, this.headerKey, 0, 32);

		// Create key specs (reused across packets)
		this.mainKeySpec = new SecretKeySpec(this.mainKey, "ChaCha20");
		this.headerKeySpec = new SecretKeySpec(this.headerKey, "ChaCha20");

		// Pre-create cipher instances
		try
		{
			this.headerCipher = Cipher.getInstance("ChaCha20");
			this.polyKeyCipher = Cipher.getInstance("ChaCha20");
			this.payloadCipher = Cipher.getInstance("ChaCha20");
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("ChaCha20 cipher not available", e);
		}
	}

	@Override
	public int getKeySize()
	{
		return KEY_SIZE;
	}

	@Override
	public int getTagSize()
	{
		return TAG_SIZE;
	}

	/**
	 * Update nonce with SSH sequence number.
	 *
	 * SSH uses 32-bit sequence numbers, but ChaCha20 needs 12-byte nonce:
	 * - Bytes 0-7: 0x0000000000000000 (always zero)
	 * - Bytes 8-11: sequence number in big-endian
	 *
	 * When using IvParameterSpec, the provider manages the block counter internally.
	 * This method reuses the instance nonce buffer to avoid allocations.
	 *
	 * @param seqNum SSH packet sequence number
	 */
	private void updateNonce(int seqNum)
	{
		nonce[8] = (byte) (seqNum >>> 24);
		nonce[9] = (byte) (seqNum >>> 16);
		nonce[10] = (byte) (seqNum >>> 8);
		nonce[11] = (byte) seqNum;
	}

	@Override
	public void encryptPacketLength(int seqNum, byte[] plainLength, byte[] dest, int destOff)
	{
		try
		{
			updateNonce(seqNum);
			AlgorithmParameterSpec params = ChaCha20ParamFactory.create(nonce, 0);
			headerCipher.init(Cipher.ENCRYPT_MODE, headerKeySpec, params);

			int len = headerCipher.doFinal(plainLength, 0, 4, dest, destOff);
			if (len != 4)
			{
				throw new IllegalStateException("Unexpected encrypted length: " + len);
			}
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("ChaCha20 encryption failed", e);
		}
	}

	@Override
	public void decryptPacketLength(int seqNum, byte[] encryptedLength, byte[] dest, int destOff)
	{
		try
		{
			updateNonce(seqNum);
			AlgorithmParameterSpec params = ChaCha20ParamFactory.create(nonce, 0);
			headerCipher.init(Cipher.DECRYPT_MODE, headerKeySpec, params);

			int len = headerCipher.doFinal(encryptedLength, 0, 4, dest, destOff);
			if (len != 4)
			{
				throw new IllegalStateException("Unexpected decrypted length: " + len);
			}
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("ChaCha20 decryption failed", e);
		}
	}

	@Override
	public void seal(int seqNum, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] encryptedLength)
	{
		try
		{
			updateNonce(seqNum);

			if (ChaCha20ParamFactory.usesChaCha20ParameterSpec())
			{
				AlgorithmParameterSpec polyKeyParams = ChaCha20ParamFactory.create(nonce, 0);
				polyKeyCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, polyKeyParams);

				int keyLen = polyKeyCipher.doFinal(polyKeyZeros, 0, 32, polyKey, 0);
				if (keyLen != 32)
				{
					throw new IllegalStateException("Unexpected Poly1305 key length: " + keyLen);
				}

				AlgorithmParameterSpec payloadParams = ChaCha20ParamFactory.create(nonce, 1);
				payloadCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, payloadParams);

				int encLen = payloadCipher.doFinal(plaintext, 0, plaintext.length, ciphertext, 0);
				if (encLen != plaintext.length)
				{
					throw new IllegalStateException("Unexpected ciphertext length: " + encLen);
				}
			}
			else
			{
				AlgorithmParameterSpec params = ChaCha20ParamFactory.create(nonce, 0);
				payloadCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, params);

				int keyLen = payloadCipher.update(polyKeyZeros, 0, 32, polyKey, 0);
				if (keyLen != 32)
				{
					throw new IllegalStateException("Unexpected Poly1305 key length: " + keyLen);
				}

				payloadCipher.update(skipToNextBlock, 0, 32, skipToNextBlock, 0);

				int encLen = payloadCipher.doFinal(plaintext, 0, plaintext.length, ciphertext, 0);
				if (encLen != plaintext.length)
				{
					throw new IllegalStateException("Unexpected ciphertext length: " + encLen);
				}
			}

			poly.init(polyKey);
			poly.update(encryptedLength, 0, 4);
			poly.update(ciphertext, 0, ciphertext.length);
			poly.finish(tag, 0);

			Arrays.fill(polyKey, (byte) 0);
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("ChaCha20-Poly1305 seal failed", e);
		}
	}

	@Override
	public boolean open(int seqNum, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] encryptedLength) throws IOException
	{
		try
		{
			updateNonce(seqNum);

			if (ChaCha20ParamFactory.usesChaCha20ParameterSpec())
			{
				AlgorithmParameterSpec polyKeyParams = ChaCha20ParamFactory.create(nonce, 0);
				polyKeyCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, polyKeyParams);

				int keyLen = polyKeyCipher.doFinal(polyKeyZeros, 0, 32, polyKey, 0);
				if (keyLen != 32)
				{
					throw new IOException("Unexpected Poly1305 key length: " + keyLen);
				}

				poly.init(polyKey);
				poly.update(encryptedLength, 0, 4);
				poly.update(ciphertext, 0, ciphertext.length);
				poly.finish(computedTag, 0);

				boolean tagValid = constantTimeEquals(tag, computedTag);

				Arrays.fill(computedTag, (byte) 0);
				Arrays.fill(polyKey, (byte) 0);

				if (!tagValid)
				{
					return false;
				}

				AlgorithmParameterSpec payloadParams = ChaCha20ParamFactory.create(nonce, 1);
				payloadCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, payloadParams);

				int decLen = payloadCipher.doFinal(ciphertext, 0, ciphertext.length, plaintext, 0);
				if (decLen != ciphertext.length)
				{
					throw new IOException("Unexpected decrypted length: " + decLen);
				}
			}
			else
			{
				AlgorithmParameterSpec params = ChaCha20ParamFactory.create(nonce, 0);
				payloadCipher.init(Cipher.ENCRYPT_MODE, mainKeySpec, params);

				int keyLen = payloadCipher.update(polyKeyZeros, 0, 32, polyKey, 0);
				if (keyLen != 32)
				{
					throw new IOException("Unexpected Poly1305 key length: " + keyLen);
				}

				poly.init(polyKey);
				poly.update(encryptedLength, 0, 4);
				poly.update(ciphertext, 0, ciphertext.length);
				poly.finish(computedTag, 0);

				boolean tagValid = constantTimeEquals(tag, computedTag);

				Arrays.fill(computedTag, (byte) 0);
				Arrays.fill(polyKey, (byte) 0);

				if (!tagValid)
				{
					return false;
				}

				payloadCipher.update(skipToNextBlock, 0, 32, skipToNextBlock, 0);

				int decLen = payloadCipher.doFinal(ciphertext, 0, ciphertext.length, plaintext, 0);
				if (decLen != ciphertext.length)
				{
					throw new IOException("Unexpected decrypted length: " + decLen);
				}
			}

			return true;
		}
		catch (GeneralSecurityException e)
		{
			return false;
		}
	}

	/**
	 * Constant-time equality comparison to prevent timing attacks.
	 */
	private boolean constantTimeEquals(byte[] a, byte[] b)
	{
		if (a.length != b.length)
		{
			return false;
		}

		int result = 0;
		for (int i = 0; i < a.length; i++)
		{
			result |= a[i] ^ b[i];
		}
		return result == 0;
	}

	@Override
	public int getBlockSize() {
		return BLOCK_SIZE;
	}
}

package com.trilead.ssh2.crypto.cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * AES-GCM AEAD cipher implementation for SSH.
 *
 * Implements aes128-gcm@openssh.com and aes256-gcm@openssh.com as specified in:
 * - RFC 5647: AES Galois Counter Mode for SSH Transport Layer Protocol
 * - draft-miller-sshm-aes-gcm-00: OpenSSH modifications fixing RFC 5647 negotiation
 *
 * Packet format:
 *   [4 bytes plaintext length (AAD)] [encrypted payload] [16 bytes GCM tag]
 *
 * Nonce construction:
 *   [4 bytes fixed IV] [8 bytes invocation counter]
 *
 * @author Kenny Root
 */
public class AesGcm implements AeadCipher
{
	public static final int BLOCK_SIZE = 16;
	public static final int TAG_SIZE = 16;  // 128 bits
	public static final int NONCE_SIZE = 12; // 96 bits
	public static final int FIXED_IV_SIZE = 4; // First 4 bytes of initial IV

	private final int keyBytes;
	private SecretKeySpec keySpec;
	private byte[] nonce;
	private byte[] initialNonce;
	private boolean forEncryption;

	private Cipher cipher;

	private byte[] tempBuffer;
	private int tempBufferSize = 0;

	/**
	 * Create an AES-GCM cipher instance.
	 *
	 * @param keyBits key size in bits (128 or 256)
	 * @throws IllegalArgumentException if keyBits is not 128 or 256
	 */
	public AesGcm(int keyBits) throws IllegalArgumentException
	{
		if (keyBits != 128 && keyBits != 256)
		{
			throw new IllegalArgumentException("Key size must be 128 or 256 bits");
		}
		this.keyBytes = keyBits / 8;
	}

	@Override
	public void init(boolean forEncryption, byte[] key, byte[] iv) throws IllegalArgumentException
	{
		if (key.length != keyBytes)
		{
			throw new IllegalArgumentException(
				"Invalid key length: expected " + keyBytes + ", got " + key.length);
		}

		if (iv.length != NONCE_SIZE)
		{
			throw new IllegalArgumentException(
				"Invalid IV length: expected " + NONCE_SIZE + ", got " + iv.length);
		}

		this.forEncryption = forEncryption;

		this.keySpec = new SecretKeySpec(key, "AES");

		this.nonce = new byte[NONCE_SIZE];
		System.arraycopy(iv, 0, this.nonce, 0, NONCE_SIZE);

		this.initialNonce = new byte[NONCE_SIZE];
		System.arraycopy(this.nonce, 0, this.initialNonce, 0, NONCE_SIZE);

		try
		{
			this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("AES/GCM/NoPadding not available", e);
		}
	}

	@Override
	public int getKeySize()
	{
		return keyBytes;
	}

	@Override
	public int getTagSize()
	{
		return TAG_SIZE;
	}

	/**
	 * Ensure the temporary buffer is at least the specified size.
	 * Reuses existing buffer if large enough to reduce allocations.
	 */
	private void ensureTempBufferSize(int requiredSize)
	{
		if (tempBuffer == null || tempBufferSize < requiredSize)
		{
			tempBuffer = new byte[requiredSize];
			tempBufferSize = requiredSize;
		}
	}

	/**
	 * Increment the nonce for the next packet.
	 *
	 * The nonce is treated as a 96-bit (12-byte) big-endian counter that is incremented
	 * after each packet.
	 */
	private void incrementNonce()
	{
		for (int i = NONCE_SIZE - 1; i >= 0; i--)
		{
			nonce[i]++;
			if (nonce[i] != 0)
			{
				break;
			}
		}

		if (Arrays.equals(nonce, initialNonce))
		{
			throw new IllegalStateException("GCM nonce counter wrapped - rekey required");
		}
	}

	@Override
	public void encryptPacketLength(int seqNum, byte[] plainLength, byte[] dest, int destOff)
	{
		// AES-GCM does NOT encrypt the packet length (it's used as AAD instead)
		System.arraycopy(plainLength, 0, dest, destOff, 4);
	}

	@Override
	public void decryptPacketLength(int seqNum, byte[] encryptedLength, byte[] dest, int destOff)
	{
		// AES-GCM does NOT encrypt the packet length (it's plaintext AAD)
		System.arraycopy(encryptedLength, 0, dest, destOff, 4);
	}

	@Override
	public void seal(int seqNum, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] encryptedLength)
	{
		if (!forEncryption)
		{
			throw new IllegalStateException("AES-GCM not initialized for encryption");
		}

		try
		{
			GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE * 8, nonce);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

			cipher.updateAAD(encryptedLength, 0, 4);

			int requiredSize = plaintext.length + TAG_SIZE;
			ensureTempBufferSize(requiredSize);

			int outputLen = cipher.doFinal(plaintext, 0, plaintext.length, tempBuffer, 0);

			System.arraycopy(tempBuffer, 0, ciphertext, 0, plaintext.length);
			System.arraycopy(tempBuffer, plaintext.length, tag, 0, TAG_SIZE);

			incrementNonce();
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("AES-GCM encryption failed", e);
		}
	}

	@Override
	public boolean open(int seqNum, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] encryptedLength)
	{
		if (forEncryption)
		{
			throw new IllegalStateException("AES-GCM not initialized for decryption");
		}

		try
		{
			GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE * 8, nonce);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

			cipher.updateAAD(encryptedLength, 0, 4);

			int requiredSize = ciphertext.length + TAG_SIZE;
			ensureTempBufferSize(requiredSize);

			System.arraycopy(ciphertext, 0, tempBuffer, 0, ciphertext.length);
			System.arraycopy(tag, 0, tempBuffer, ciphertext.length, TAG_SIZE);

			int outputLen = cipher.doFinal(tempBuffer, 0, requiredSize, plaintext, 0);

			incrementNonce();

			return true;
		}
		catch (GeneralSecurityException e)
		{
			return false;
		}
	}

	@Override
	public int getBlockSize() {
		return BLOCK_SIZE;
	}

	/**
	 * AES-128-GCM cipher (16-byte key + 12-byte IV = 28 bytes key material).
	 */
	public static class AES128 extends AesGcm
	{
		public AES128()
		{
			super(128);
		}
	}

	/**
	 * AES-256-GCM cipher (32-byte key + 12-byte IV = 44 bytes key material).
	 */
	public static class AES256 extends AesGcm
	{
		public AES256()
		{
			super(256);
		}
	}
}

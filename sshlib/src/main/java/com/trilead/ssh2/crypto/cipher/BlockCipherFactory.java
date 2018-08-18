
package com.trilead.ssh2.crypto.cipher;

import java.lang.reflect.Constructor;
import java.util.ArrayList;

/**
 * BlockCipherFactory.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: BlockCipherFactory.java,v 1.2 2008/04/01 12:38:09 cplattne Exp $
 */
public class BlockCipherFactory
{
	private static class CipherEntry
	{
		final String type;
		final int blocksize;
		final int keysize;
		final String cipherClass;

		CipherEntry(String type, int blockSize, int keySize, String cipherClass)
		{
			this.type = type;
			this.blocksize = blockSize;
			this.keysize = keySize;
			this.cipherClass = cipherClass;
		}
	}

	private static final ArrayList<CipherEntry> ciphers = new ArrayList<>();

	static
	{
		/* Higher Priority First */

		ciphers.add(new CipherEntry("aes256-ctr", 16, 32, "com.trilead.ssh2.crypto.cipher.AES$CTR"));
		ciphers.add(new CipherEntry("aes128-ctr", 16, 16, "com.trilead.ssh2.crypto.cipher.AES$CTR"));
		ciphers.add(new CipherEntry("blowfish-ctr", 8, 16, "com.trilead.ssh2.crypto.cipher.BlowFish$CTR"));

		ciphers.add(new CipherEntry("aes256-cbc", 16, 32, "com.trilead.ssh2.crypto.cipher.AES$CBC"));
		ciphers.add(new CipherEntry("aes128-cbc", 16, 16, "com.trilead.ssh2.crypto.cipher.AES$CBC"));
		ciphers.add(new CipherEntry("blowfish-cbc", 8, 16, "com.trilead.ssh2.crypto.cipher.BlowFish$CBC"));
		
		ciphers.add(new CipherEntry("3des-ctr", 8, 24, "com.trilead.ssh2.crypto.cipher.DESede$CTR"));
		ciphers.add(new CipherEntry("3des-cbc", 8, 24, "com.trilead.ssh2.crypto.cipher.DESede$CBC"));
	}

	public static String[] getDefaultCipherList()
	{
		String list[] = new String[ciphers.size()];
		for (int i = 0; i < ciphers.size(); i++)
		{
			CipherEntry ce = ciphers.get(i);
			list[i] = ce.type;
		}
		return list;
	}

	public static void checkCipherList(String[] cipherCandidates)
	{
		for (String cipherCandidate : cipherCandidates)
			getEntry(cipherCandidate);
	}

	public static BlockCipher createCipher(String type, boolean encrypt, byte[] key, byte[] iv)
	{
		try
		{
			CipherEntry ce = getEntry(type);
			Class cc = Class.forName(ce.cipherClass);
			Constructor<BlockCipher> constructor = cc.getConstructor();
			BlockCipher bc = constructor.newInstance();
			bc.init(encrypt, key, iv);
			return bc;
		}
		catch (Exception e)
		{
			throw new IllegalArgumentException("Cannot instantiate " + type, e);
		}
	}

	private static CipherEntry getEntry(String type)
	{
		for (CipherEntry ce : ciphers) {
			if (ce.type.equals(type))
				return ce;
		}
		throw new IllegalArgumentException("Unknown algorithm " + type);
	}

	public static int getBlockSize(String type)
	{
		CipherEntry ce = getEntry(type);
		return ce.blocksize;
	}

	public static int getKeySize(String type)
	{
		CipherEntry ce = getEntry(type);
		return ce.keysize;
	}
}

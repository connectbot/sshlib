
package com.trilead.ssh2.crypto.digest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 * MAC.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: MAC.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public final class MACs
{
	/* Higher Priority First */
	private static final String[] MAC_LIST = {
			HMAC.HMAC_SHA2_256_ETM,
			HMAC.HMAC_SHA2_512_ETM,
			HMAC.HMAC_SHA1_ETM,
			HMAC.HMAC_SHA2_256,
			HMAC.HMAC_SHA2_512,
			HMAC.HMAC_SHA1,
	};

	public final static String[] getMacList()
	{
		return MAC_LIST;
	}

	public final static void checkMacList(String[] macs)
	{
		for (int i = 0; i < macs.length; i++) {
			getKeyLen(macs[i]);
		}
	}

	public final static int getKeyLen(String type)
	{
		if (type == null)
			throw new IllegalArgumentException("type == null");

		if (type.startsWith(HMAC.HMAC_SHA1))
			return 20;
		if (type.startsWith(HMAC.HMAC_MD5))
			return 16;
		if (type.startsWith(HMAC.HMAC_SHA2_256))
			return 32;
		if (type.startsWith(HMAC.HMAC_SHA2_512))
			return 64;

		throw new IllegalArgumentException("Unknown algorithm " + type);
	}
}

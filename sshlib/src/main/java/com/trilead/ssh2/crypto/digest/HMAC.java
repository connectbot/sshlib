
package com.trilead.ssh2.crypto.digest;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * MAC.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: MAC.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public final class HMAC implements MAC
{
	private static final String ETM_SUFFIX = "-etm@openssh.com";

	/**
	 * From http://tools.ietf.org/html/rfc4253
	 */
	static final String HMAC_MD5 = "hmac-md5";

	/**
	 * From http://tools.ietf.org/html/rfc4253
	 */
	static final String HMAC_MD5_96 = "hmac-md5-96";

	/**
	 * From http://tools.ietf.org/html/rfc4253
	 */
	static final String HMAC_SHA1 = "hmac-sha1";

	/**
	 * From https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL
	 */
	static final String HMAC_SHA1_ETM = "hmac-sha1-etm@openssh.com";

	/**
	 * From http://tools.ietf.org/html/rfc4253
	 */
	static final String HMAC_SHA1_96 = "hmac-sha1-96";

	/**
	 * From https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL
	 */
	static final String HMAC_SHA2_256_ETM = "hmac-sha2-256-etm@openssh.com";

	/**
	 * From https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL
	 */
	static final String HMAC_SHA2_512_ETM = "hmac-sha2-512-etm@openssh.com";

	/**
	 * From http://tools.ietf.org/html/rfc6668
	 */
	static final String HMAC_SHA2_256 = "hmac-sha2-256";

	/**
	 * From http://tools.ietf.org/html/rfc6668
	 */
	static final String HMAC_SHA2_512 = "hmac-sha2-512";

	private final Mac mac;
	private final int outSize;
	private final boolean encryptThenMac;
	private final byte[] buffer;

	public HMAC(String type, byte[] key)
	{
		try {
			if (HMAC_SHA1.equals(type) || HMAC_SHA1_96.equals(type))
			{
				mac = Mac.getInstance("HmacSHA1");
				encryptThenMac = false;
			}
			else if (HMAC_SHA1_ETM.equals(type))
			{
				mac = Mac.getInstance("HmacSHA1");
				encryptThenMac = true;
			}
			else if (HMAC_MD5.equals(type) || HMAC_MD5_96.equals(type))
			{
				mac = Mac.getInstance("HmacMD5");
				encryptThenMac = false;
			}
			else if (HMAC_SHA2_256.equals(type))
			{
				mac = Mac.getInstance("HmacSHA256");
				encryptThenMac = false;
			}
			else if (HMAC_SHA2_256_ETM.equals(type))
			{
				mac = Mac.getInstance("HmacSHA256");
				encryptThenMac = true;
			}
			else if (HMAC_SHA2_512.equals(type))
			{
				mac = Mac.getInstance("HmacSHA512");
				encryptThenMac = false;
			}
			else if (HMAC_SHA2_512_ETM.equals(type))
			{
				mac = Mac.getInstance("HmacSHA512");
				encryptThenMac = true;
			}
			else
				throw new IllegalArgumentException("Unknown algorithm " + type);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Unknown algorithm " + type, e);
		}

		int macSize = mac.getMacLength();
		if (type.endsWith("-96")) {
			outSize = 12;
			buffer = new byte[macSize];
		} else {
			outSize = macSize;
			buffer = null;
		}

		try {
			mac.init(new SecretKeySpec(key, type));
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public final void initMac(int seq)
	{
		mac.reset();
		mac.update((byte) (seq >> 24));
		mac.update((byte) (seq >> 16));
		mac.update((byte) (seq >> 8));
		mac.update((byte) (seq));
	}

	public final void update(byte[] packetdata, int off, int len)
	{
		mac.update(packetdata, off, len);
	}

	public final void getMac(byte[] out, int off)
	{
		try {
			if (buffer != null) {
				mac.doFinal(buffer, 0);
				System.arraycopy(buffer, 0, out, off, out.length - off);
			} else {
				mac.doFinal(out, off);
			}
		} catch (ShortBufferException e) {
			throw new IllegalStateException(e);
		}
	}

	public final int size()
	{
		return outSize;
	}

	public boolean isEncryptThenMac() {
		return encryptThenMac;
	}
}

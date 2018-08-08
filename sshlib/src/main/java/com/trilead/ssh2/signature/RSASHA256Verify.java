package com.trilead.ssh2.signature;

import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class RSASHA256Verify
{
	private static final Logger log = Logger.getLogger(RSASHA256Verify.class);

	public static byte[] decodeRSASHA256Signature(byte[] sig) throws IOException
	{
		TypesReader tr = new TypesReader(sig);

		String sig_format = tr.readString();

		if (!sig_format.equals("rsa-sha2-256"))
			throw new IOException("Peer sent wrong signature format");

		/* S is NOT an MPINT. "The value for 'rsa_signature_blob' is encoded as a string
		 * containing s (which is an integer, without lengths or padding, unsigned and in
		 * network byte order)." See also below.
		 */

		byte[] s = tr.readByteString();

		if (s.length == 0)
			throw new IOException("Error in RSA signature, S is empty.");

		if (log.isEnabled())
		{
			log.log(80, "Decoding rsa-sha2-256 signature string (length: " + s.length + ")");
		}

		if (tr.remain() != 0)
			throw new IOException("Padding in RSA signature!");

		if (s[0] == 0 && s[1] == 0 && s[2] == 0) {
			int i = 0;
			int j = ((s[i++] << 24) & 0xff000000) | ((s[i++] << 16) & 0x00ff0000)
					| ((s[i++] << 8) & 0x0000ff00) | ((s[i++]) & 0x000000ff);
			i += j;
			j = ((s[i++] << 24) & 0xff000000) | ((s[i++] << 16) & 0x00ff0000)
					| ((s[i++] << 8) & 0x0000ff00) | ((s[i++]) & 0x000000ff);
			byte[] tmp = new byte[j];
			System.arraycopy(s, i, tmp, 0, j);
			sig = tmp;
		}

		return s;
	}

	public static byte[] encodeRSASHA256Signature(byte[] s) throws IOException
	{
		TypesWriter tw = new TypesWriter();

		tw.writeString("rsa-sha2-256");

		/* S is NOT an MPINT. "The value for 'rsa_signature_blob' is encoded as a string
		 * containing s (which is an integer, without lengths or padding, unsigned and in
		 * network byte order)."
		 */

		/* Remove first zero sign byte, if present */

		if ((s.length > 1) && (s[0] == 0x00))
			tw.writeString(s, 1, s.length - 1);
		else
			tw.writeString(s, 0, s.length);

		return tw.getBytes();
	}

	public static byte[] generateSignature(byte[] message, RSAPrivateKey pk) throws IOException
	{
		try {
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initSign(pk);
			s.update(message);
			return s.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		}
	}

	public static boolean verifySignature(byte[] message, byte[] ds, RSAPublicKey dpk) throws IOException
	{
		try {
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initVerify(dpk);
			s.update(message);
			return s.verify(ds);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		}
	}
}

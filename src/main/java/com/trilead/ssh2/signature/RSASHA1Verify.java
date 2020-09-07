
package com.trilead.ssh2.signature;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;


/**
 * RSASHA1Verify.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: RSASHA1Verify.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public class RSASHA1Verify implements SSHSignature
{
	private static final Logger log = Logger.getLogger(RSASHA1Verify.class);
	public static final String ID_SSH_RSA = "ssh-rsa";

	private static class InstanceHolder {
		private static RSASHA1Verify sInstance = new RSASHA1Verify();
	}

	private RSASHA1Verify() {}

	public static RSASHA1Verify get() {
		return RSASHA1Verify.InstanceHolder.sInstance;
	}

	@Override
	public String getKeyFormat() {
		return ID_SSH_RSA;
	}

	public PublicKey decodePublicKey(byte[] key) throws IOException
	{
		TypesReader tr = new TypesReader(key);

		String key_format = tr.readString();

		if (!key_format.equals(ID_SSH_RSA))
			throw new IllegalArgumentException("This is not a ssh-rsa public key");

		BigInteger e = tr.readMPINT();
		BigInteger n = tr.readMPINT();

		if (tr.remain() != 0)
			throw new IOException("Padding in RSA public key!");

		KeySpec keySpec = new RSAPublicKeySpec(n, e);

		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException nsae) {
			throw new IOException("No RSA KeyFactory available", nsae);
		}
	}

	public byte[] encodePublicKey(PublicKey pk) throws IOException
	{
		RSAPublicKey rsaPublicKey = (RSAPublicKey) pk;

		TypesWriter tw = new TypesWriter();

		tw.writeString(ID_SSH_RSA);
		tw.writeMPInt(rsaPublicKey.getPublicExponent());
		tw.writeMPInt(rsaPublicKey.getModulus());

		return tw.getBytes();
	}

	private static byte[] decodeSignature(byte[] sig) throws IOException
	{
		TypesReader tr = new TypesReader(sig);

		String sig_format = tr.readString();

		if (!sig_format.equals(ID_SSH_RSA))
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
			log.log(80, "Decoding ssh-rsa signature string (length: " + s.length + ")");
		}

		if (tr.remain() != 0)
			throw new IOException("Padding in RSA signature!");

		return s;
	}

	private static byte[] encodeSignature(byte[] s) throws IOException
	{
		TypesWriter tw = new TypesWriter();

		tw.writeString(ID_SSH_RSA);

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

	public byte[] generateSignature(byte[] message, PrivateKey pk, SecureRandom secureRandom) throws IOException
	{
		try {
			Signature s = Signature.getInstance("SHA1withRSA");
			s.initSign(pk, secureRandom);
			s.update(message);
			return encodeSignature(s.sign());
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		}
	}

	public boolean verifySignature(byte[] message, byte[] sshSig, PublicKey dpk) throws IOException
	{
		byte[] javaSig = decodeSignature(sshSig);
		try {
			Signature s = Signature.getInstance("SHA1withRSA");
			s.initVerify(dpk);
			s.update(message);
			return s.verify(javaSig);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		}
	}
}

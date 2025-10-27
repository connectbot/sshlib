package com.trilead.ssh2.signature;

import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

/**
 * RSA signature verification using SHA-256 hash algorithm for SSH.
 * <p>
 * Implements the rsa-sha2-256 signature algorithm defined in RFC 8332.
 *
 * @see SSHSignature
 * @see RSASHA512Verify
 */
public class RSASHA256Verify implements SSHSignature
{
	private static final Logger log = Logger.getLogger(RSASHA256Verify.class);
	public static final String ID_RSA_SHA_2_256 = "rsa-sha2-256";

	private static class InstanceHolder {
		private static RSASHA256Verify sInstance = new RSASHA256Verify();
	}

	private RSASHA256Verify() {
	}

	public static RSASHA256Verify get() {
		return RSASHA256Verify.InstanceHolder.sInstance;
	}

	private static byte[] decodeRSASHA256Signature(byte[] sig) throws IOException
	{
		TypesReader tr = new TypesReader(sig);

		String sig_format = tr.readString();

		if (!sig_format.equals(ID_RSA_SHA_2_256))
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

		return s;
	}

	private static byte[] encodeRSASHA256Signature(byte[] s) throws IOException
	{
		TypesWriter tw = new TypesWriter();

		tw.writeString(ID_RSA_SHA_2_256);

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

	@Override
	public byte[] generateSignature(byte[] message, PrivateKey privateKey, SecureRandom secureRandom) throws IOException
	{
		try {
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initSign(privateKey, secureRandom);
			s.update(message);
			return encodeRSASHA256Signature(s.sign());
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getKeyFormat() {
		return ID_RSA_SHA_2_256;
	}

	@Override
	public PublicKey decodePublicKey(byte[] encoded) throws IOException {
		return RSASHA1Verify.get().decodePublicKey(encoded);
	}

	@Override
	public byte[] encodePublicKey(PublicKey publicKey) throws IOException {
		return RSASHA1Verify.get().encodePublicKey(publicKey);
	}

	@Override
	public boolean verifySignature(byte[] message, byte[] sshSig, PublicKey dpk) throws IOException
	{
		byte[] javaSig = decodeRSASHA256Signature(sshSig);

		try {
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initVerify(dpk);
			s.update(message);
			return s.verify(javaSig);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		}
	}
}

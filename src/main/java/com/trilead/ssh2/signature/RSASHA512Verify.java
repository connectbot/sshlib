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

public class RSASHA512Verify implements SSHSignature
{
	private static final Logger log = Logger.getLogger(RSASHA512Verify.class);
	public static final String ID_RSA_SHA_2_512 = "rsa-sha2-512";

	private static class InstanceHolder {
		private static final RSASHA512Verify sInstance = new RSASHA512Verify();
	}

	private RSASHA512Verify() {
	}

	public static RSASHA512Verify get() {
		return RSASHA512Verify.InstanceHolder.sInstance;
	}

	private static byte[] decodeRSASHA512Signature(byte[] sig) throws IOException
	{
		TypesReader tr = new TypesReader(sig);

		String sig_format = tr.readString();

		if (!sig_format.equals(ID_RSA_SHA_2_512))
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
			log.log(80, "Decoding rsa-sha2-512 signature string (length: " + s.length + ")");
		}

		if (tr.remain() != 0)
			throw new IOException("Padding in RSA signature!");

		return s;
	}

	private static byte[] encodeRSASHA512Signature(byte[] s)
	{
		TypesWriter tw = new TypesWriter();

		tw.writeString(ID_RSA_SHA_2_512);

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
			// Android's Signature is guaranteed to support this instance
			Signature s = Signature.getInstance("SHA512withRSA");
			s.initSign(privateKey, secureRandom);
			s.update(message);
			return encodeRSASHA512Signature(s.sign());
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getKeyFormat() {
		return ID_RSA_SHA_2_512;
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
	public boolean verifySignature(byte[] message, byte[] sshSig, PublicKey publicKey) throws IOException
	{
		byte[] javaSig = decodeRSASHA512Signature(sshSig);
		try {
			Signature s = Signature.getInstance("SHA512withRSA");
			s.initVerify(publicKey);
			s.update(message);
			return s.verify(javaSig);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		}
	}
}

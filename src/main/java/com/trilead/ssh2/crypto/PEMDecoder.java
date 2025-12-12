
package com.trilead.ssh2.crypto;

import java.io.BufferedReader;
import java.io.CharArrayReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import com.trilead.ssh2.signature.ECDSASHA2Verify;

/**
 * PEM Support.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: PEMDecoder.java,v 1.2 2008/04/01 12:38:09 cplattne Exp $
 */
public class PEMDecoder
{
	public static final int PEM_RSA_PRIVATE_KEY = 1;
	public static final int PEM_DSA_PRIVATE_KEY = 2;
	public static final int PEM_EC_PRIVATE_KEY = 3;
	public static final int PEM_OPENSSH_PRIVATE_KEY = 4;

	private static int hexToInt(char c)
	{
		if ((c >= 'a') && (c <= 'f'))
		{
			return (c - 'a') + 10;
		}

		if ((c >= 'A') && (c <= 'F'))
		{
			return (c - 'A') + 10;
		}

		if ((c >= '0') && (c <= '9'))
		{
			return (c - '0');
		}

		throw new IllegalArgumentException("Need hex char");
	}

	private static byte[] hexToByteArray(String hex)
	{
		if (hex == null)
			throw new IllegalArgumentException("null argument");

		if ((hex.length() % 2) != 0)
			throw new IllegalArgumentException("Uneven string length in hex encoding.");

		byte decoded[] = new byte[hex.length() / 2];

		for (int i = 0; i < decoded.length; i++)
		{
			int hi = hexToInt(hex.charAt(i * 2));
			int lo = hexToInt(hex.charAt((i * 2) + 1));

			decoded[i] = (byte) (hi * 16 + lo);
		}

		return decoded;
	}

	public static final PEMStructure parsePEM(char[] pem) throws IOException
	{
		PEMStructure ps = new PEMStructure();

		String line = null;

		BufferedReader br = new BufferedReader(new CharArrayReader(pem));

		String endLine = null;

		while (true)
		{
			line = br.readLine();

			if (line == null)
				throw new IOException("Invalid PEM structure, '-----BEGIN...' missing");

			line = line.trim();

			if (line.startsWith("-----BEGIN DSA PRIVATE KEY-----"))
			{
				endLine = "-----END DSA PRIVATE KEY-----";
				ps.pemType = PEM_DSA_PRIVATE_KEY;
				break;
			}

			if (line.startsWith("-----BEGIN RSA PRIVATE KEY-----"))
			{
				endLine = "-----END RSA PRIVATE KEY-----";
				ps.pemType = PEM_RSA_PRIVATE_KEY;
				break;
			}

			if (line.startsWith("-----BEGIN EC PRIVATE KEY-----")) {
				endLine = "-----END EC PRIVATE KEY-----";
				ps.pemType = PEM_EC_PRIVATE_KEY;
				break;
			}

			if (line.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----")) {
				endLine = "-----END OPENSSH PRIVATE KEY-----";
				ps.pemType = PEM_OPENSSH_PRIVATE_KEY;
				break;
			}
		}

		while (true)
		{
			line = br.readLine();

			if (line == null)
				throw new IOException("Invalid PEM structure, " + endLine + " missing");

			line = line.trim();

			int sem_idx = line.indexOf(':');

			if (sem_idx == -1)
				break;

			String name = line.substring(0, sem_idx + 1);
			String value = line.substring(sem_idx + 1);

			String values[] = value.split(",");

			for (int i = 0; i < values.length; i++)
				values[i] = values[i].trim();

			// Proc-Type: 4,ENCRYPTED
			// DEK-Info: DES-EDE3-CBC,579B6BE3E5C60483

			if ("Proc-Type:".equals(name))
			{
				ps.procType = values;
				continue;
			}

			if ("DEK-Info:".equals(name))
			{
				ps.dekInfo = values;
				continue;
			}
			/* Ignore line */
		}

		StringBuffer keyData = new StringBuffer();

		while (true)
		{
			if (line == null)
				throw new IOException("Invalid PEM structure, " + endLine + " missing");

			line = line.trim();

			if (line.startsWith(endLine))
				break;

			keyData.append(line);

			line = br.readLine();
		}

		char[] pem_chars = new char[keyData.length()];
		keyData.getChars(0, pem_chars.length, pem_chars, 0);

		ps.data = Base64.decode(pem_chars);

		if (ps.data.length == 0)
			throw new IOException("Invalid PEM structure, no data available");

		return ps;
	}

	private static void decryptPEM(PEMStructure ps, byte[] pw) throws IOException
	{
		if (ps.dekInfo == null)
			throw new IOException("Broken PEM, no mode and salt given, but encryption enabled");

		if (ps.dekInfo.length != 2)
			throw new IOException("Broken PEM, DEK-Info is incomplete!");

		String algo = ps.dekInfo[0];
		byte[] salt = hexToByteArray(ps.dekInfo[1]);

		byte[] dz = CommonDecoder.decryptData(ps.data, pw, salt, -1, algo);

		ps.data = dz;
		ps.dekInfo = null;
		ps.procType = null;
	}

	public static final boolean isPEMEncrypted(PEMStructure ps) throws IOException
	{
		if (ps.pemType == PEM_OPENSSH_PRIVATE_KEY) {
			return OpenSSHKeyDecoder.isEncrypted(ps.data);
		}

		if (ps.procType == null)
			return false;

		if (ps.procType.length != 2)
			throw new IOException("Unknown Proc-Type field.");

		if (!"4".equals(ps.procType[0]))
			throw new IOException("Unknown Proc-Type field (" + ps.procType[0] + ")");

		return "ENCRYPTED".equals(ps.procType[1]);

	}

	public static KeyPair decode(char[] pem, String password) throws IOException
	{
		PEMStructure ps = parsePEM(pem);
		return decode(ps, password);
	}

	public static KeyPair decode(PEMStructure ps, String password) throws IOException
	{
		if (isPEMEncrypted(ps) && ps.pemType != PEM_OPENSSH_PRIVATE_KEY)
		{
			if (password == null)
				throw new IOException("PEM is encrypted, but no password was specified");

			try {
				decryptPEM(ps, password.getBytes("ISO-8859-1"));
			} catch (UnsupportedEncodingException e) {
				decryptPEM(ps, password.getBytes("ISO-8859-1"));
			}
		}

		if (ps.pemType == PEM_DSA_PRIVATE_KEY)
		{
			SimpleDERReader dr = new SimpleDERReader(ps.data);

			byte[] seq = dr.readSequenceAsByteArray();

			if (dr.available() != 0)
				throw new IOException("Padding in DSA PRIVATE KEY DER stream.");

			dr.resetInput(seq);

			BigInteger version = dr.readInt();

			if (version.compareTo(BigInteger.ZERO) != 0)
				throw new IOException("Wrong version (" + version + ") in DSA PRIVATE KEY DER stream.");

			BigInteger p = dr.readInt();
			BigInteger q = dr.readInt();
			BigInteger g = dr.readInt();
			BigInteger y = dr.readInt();
			BigInteger x = dr.readInt();

			if (dr.available() != 0)
				throw new IOException("Padding in DSA PRIVATE KEY DER stream.");

			DSAPrivateKeySpec privSpec = new DSAPrivateKeySpec(x, p, q, g);
			DSAPublicKeySpec pubSpec = new DSAPublicKeySpec(y, p, q, g);

			return generateKeyPair("DSA", privSpec, pubSpec);
		}

		if (ps.pemType == PEM_RSA_PRIVATE_KEY)
		{
			SimpleDERReader dr = new SimpleDERReader(ps.data);

			byte[] seq = dr.readSequenceAsByteArray();

			if (dr.available() != 0)
				throw new IOException("Padding in RSA PRIVATE KEY DER stream.");

			dr.resetInput(seq);

			BigInteger version = dr.readInt();

			if ((version.compareTo(BigInteger.ZERO) != 0) && (version.compareTo(BigInteger.ONE) != 0))
				throw new IOException("Wrong version (" + version + ") in RSA PRIVATE KEY DER stream.");

			BigInteger n = dr.readInt();
			BigInteger e = dr.readInt();
			BigInteger d = dr.readInt();
			// TODO: is this right?
			BigInteger primeP = dr.readInt();
			BigInteger primeQ = dr.readInt();
			BigInteger expP = dr.readInt();
			BigInteger expQ = dr.readInt();
			BigInteger coeff = dr.readInt();

			RSAPrivateKeySpec privSpec = new RSAPrivateCrtKeySpec(n, e, d, primeP, primeQ, expP, expQ, coeff);
			RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(n, e);

			return generateKeyPair("RSA", privSpec, pubSpec);
		}

		if (ps.pemType == PEM_EC_PRIVATE_KEY) {
			SimpleDERReader dr = new SimpleDERReader(ps.data);

			byte[] seq = dr.readSequenceAsByteArray();

			if (dr.available() != 0)
				throw new IOException("Padding in EC PRIVATE KEY DER stream.");

			dr.resetInput(seq);

			BigInteger version = dr.readInt();

			if ((version.compareTo(BigInteger.ONE) != 0))
				throw new IOException("Wrong version (" + version + ") in EC PRIVATE KEY DER stream.");

			byte[] privateBytes = dr.readOctetString();

			String curveOid = null;
			byte[] publicBytes = null;
			while (dr.available() > 0) {
				int type = dr.readConstructedType();
				SimpleDERReader cr = dr.readConstructed();
				switch (type) {
				case 0:
					curveOid = cr.readOid();
					break;
				case 1:
					publicBytes = cr.readOctetString();
					break;
				}
			}

			ECDSASHA2Verify verifier = ECDSASHA2Verify.getVerifierForOID(curveOid);
			if (verifier == null)
				throw new IOException("invalid OID");

			BigInteger s = new BigInteger(1, privateBytes);
			byte[] publicBytesSlice = new byte[publicBytes.length - 1];
			System.arraycopy(publicBytes, 1, publicBytesSlice, 0, publicBytesSlice.length);
			ECParameterSpec params = verifier.getParameterSpec();
			ECPoint w = verifier.decodeECPoint(publicBytesSlice);

			ECPrivateKeySpec privSpec = new ECPrivateKeySpec(s, params);
			ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, params);

			return generateKeyPair("EC", privSpec, pubSpec);
		}

		if (ps.pemType == PEM_OPENSSH_PRIVATE_KEY) {
			return OpenSSHKeyDecoder.decode(ps.data, password);
		}

		throw new IOException("PEM problem: it is of unknown type");
	}

	/**
	 * Generate a {@code KeyPair} given an {@code algorithm} and {@code KeySpec}.
	 */
	private static KeyPair generateKeyPair(String algorithm, KeySpec privSpec, KeySpec pubSpec)
			throws IOException {
		try {
			final KeyFactory kf = KeyFactory.getInstance(algorithm);
			final PublicKey pubKey = kf.generatePublic(pubSpec);
			final PrivateKey privKey = kf.generatePrivate(privSpec);
			return new KeyPair(pubKey, privKey);
		} catch (NoSuchAlgorithmException ex) {
			throw new IOException(ex);
		} catch (InvalidKeySpecException ex) {
			throw new IOException("invalid keyspec", ex);
		}
	}
}

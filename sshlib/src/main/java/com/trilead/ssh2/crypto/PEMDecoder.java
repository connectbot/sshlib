
package com.trilead.ssh2.crypto;

import java.io.BufferedReader;
import java.io.CharArrayReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
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
import java.util.Arrays;
import java.util.Locale;

import com.trilead.ssh2.crypto.cipher.AES;
import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.cipher.DES;
import com.trilead.ssh2.crypto.cipher.DESede;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.mindrot.jbcrypt.BCrypt;

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

	private static final byte[] OPENSSH_V1_MAGIC = new byte[] {
		'o', 'p', 'e', 'n', 's', 's', 'h', '-', 'k', 'e', 'y', '-', 'v', '1', '\0',
	};

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

	private static byte[] generateKeyFromPasswordSaltWithMD5(byte[] password, byte[] salt, int keyLen)
			throws IOException
	{
		if (salt.length < 8)
			throw new IllegalArgumentException("Salt needs to be at least 8 bytes for key generation.");

		MessageDigest md5;
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("VM does not support MD5", e);
		}

		byte[] key = new byte[keyLen];
		byte[] tmp = new byte[md5.getDigestLength()];

		while (true)
		{
			md5.update(password, 0, password.length);
			md5.update(salt, 0, 8); // ARGH we only use the first 8 bytes of the
			// salt in this step.
			// This took me two hours until I got AES-xxx running.

			int copy = (keyLen < tmp.length) ? keyLen : tmp.length;

			try {
				md5.digest(tmp, 0, tmp.length);
			} catch (DigestException e) {
				throw new IOException("could not digest password", e);
			}

			System.arraycopy(tmp, 0, key, key.length - keyLen, copy);

			keyLen -= copy;

			if (keyLen == 0)
				return key;

			md5.update(tmp, 0, tmp.length);
		}
	}

	private static byte[] removePadding(byte[] buff, int blockSize) throws IOException
	{
		/* Removes RFC 1423/PKCS #7 padding */

		int rfc_1423_padding = buff[buff.length - 1] & 0xff;

		if ((rfc_1423_padding < 1) || (rfc_1423_padding > blockSize))
			throw new IOException("Decrypted PEM has wrong padding, did you specify the correct password?");

		for (int i = 2; i <= rfc_1423_padding; i++)
		{
			if (buff[buff.length - i] != rfc_1423_padding)
				throw new IOException("Decrypted PEM has wrong padding, did you specify the correct password?");
		}

		byte[] tmp = new byte[buff.length - rfc_1423_padding];
		System.arraycopy(buff, 0, tmp, 0, buff.length - rfc_1423_padding);
		return tmp;
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

	private static byte[] decryptData(byte[] data, byte[] pw, byte[] salt, int rounds, String algo) throws IOException
	{
		BlockCipher bc;
		int keySize;

		String algoLower = algo.toLowerCase(Locale.US);
		if (algoLower.equals("des-ede3-cbc"))
		{
			bc = new DESede.CBC();
			keySize = 24;
		}
		else if (algoLower.equals("des-cbc"))
		{
			bc = new DES.CBC();
			keySize = 8;
		}
		else if (algoLower.equals("aes-128-cbc") || algoLower.equals("aes128-cbc"))
		{
			bc = new AES.CBC();
			keySize = 16;
		}
		else if (algoLower.equals("aes-192-cbc") || algoLower.equals("aes192-cbc"))
		{
			bc = new AES.CBC();
			keySize = 24;
		}
		else if (algoLower.equals("aes-256-cbc") || algoLower.equals("aes256-cbc"))
		{
			bc = new AES.CBC();
			keySize = 32;
		}
		else
		{
			throw new IOException("Cannot decrypt PEM structure, unknown cipher " + algo);
		}

		if (rounds == -1)
		{
			bc.init(false, generateKeyFromPasswordSaltWithMD5(pw, salt, keySize), salt);
		}
		else
		{
			byte[] key = new byte[keySize];
			byte[] iv = new byte[bc.getBlockSize()];

			byte[] keyAndIV = new byte[key.length + iv.length];

			new BCrypt().pbkdf(pw, salt, rounds, keyAndIV);

			System.arraycopy(keyAndIV, 0, key, 0, key.length);
			System.arraycopy(keyAndIV, key.length, iv, 0, iv.length);

			bc.init(false, key, iv);
		}


		if ((data.length % bc.getBlockSize()) != 0)
			throw new IOException("Invalid PEM structure, size of encrypted block is not a multiple of "
					+ bc.getBlockSize());

		/* Now decrypt the content */
		byte[] dz = new byte[data.length];

		for (int i = 0; i < data.length / bc.getBlockSize(); i++)
		{
			bc.transformBlock(data, i * bc.getBlockSize(), dz, i * bc.getBlockSize());
		}

		if (rounds == -1) {
			/* Now check and remove RFC 1423/PKCS #7 padding */
			return removePadding(dz, bc.getBlockSize());
		} else {
			/* New style is to check the padding after reading the comment. */
			return dz;
		}
	}

	private static void decryptPEM(PEMStructure ps, byte[] pw) throws IOException
	{
		if (ps.dekInfo == null)
			throw new IOException("Broken PEM, no mode and salt given, but encryption enabled");

		if (ps.dekInfo.length != 2)
			throw new IOException("Broken PEM, DEK-Info is incomplete!");

		String algo = ps.dekInfo[0];
		byte[] salt = hexToByteArray(ps.dekInfo[1]);

		byte[] dz = decryptData(ps.data, pw, salt, -1, algo);

		ps.data = dz;
		ps.dekInfo = null;
		ps.procType = null;
	}

	public static final boolean isPEMEncrypted(PEMStructure ps) throws IOException
	{
		if (ps.pemType == PEM_OPENSSH_PRIVATE_KEY) {
			TypesReader tr = new TypesReader(ps.data);
			byte[] magic = tr.readBytes(OPENSSH_V1_MAGIC.length);
			if (!Arrays.equals(OPENSSH_V1_MAGIC, magic)) {
				throw new IOException("Could not find OPENSSH key magic: " + new String(magic, StandardCharsets.US_ASCII));
			}

			tr.readString();
			String kdfname = tr.readString();
			return !"none".equals(kdfname);
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

			decryptPEM(ps, password.getBytes(StandardCharsets.ISO_8859_1));
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

			ECParameterSpec params = ECDSASHA2Verify.getCurveForOID(curveOid);
			if (params == null)
				throw new IOException("invalid OID");

			BigInteger s = new BigInteger(1, privateBytes);
			byte[] publicBytesSlice = new byte[publicBytes.length - 1];
			System.arraycopy(publicBytes, 1, publicBytesSlice, 0, publicBytesSlice.length);
			ECPoint w = ECDSASHA2Verify.decodeECPoint(publicBytesSlice, params.getCurve());

			ECPrivateKeySpec privSpec = new ECPrivateKeySpec(s, params);
			ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, params);

			return generateKeyPair("EC", privSpec, pubSpec);
		}

		if (ps.pemType == PEM_OPENSSH_PRIVATE_KEY) {
			TypesReader tr = new TypesReader(ps.data);
			byte[] magic = tr.readBytes(OPENSSH_V1_MAGIC.length);
			if (!Arrays.equals(OPENSSH_V1_MAGIC, magic)) {
				throw new IOException("Could not find OPENSSH key magic: " + new String(magic, StandardCharsets.US_ASCII));
			}

			String ciphername = tr.readString();
			String kdfname = tr.readString();
			byte[] kdfoptions = tr.readByteString();
			int numberOfKeys = tr.readUINT32();

			// TODO support multiple keys
			if (numberOfKeys != 1) {
				throw new IOException("Only one key supported, but encountered bundle of " + numberOfKeys);
			}

			// OpenSSH discards this, so we will as well.
			tr.readByteString();

			byte[] dataBytes = tr.readByteString();

			if ("bcrypt".equals(kdfname)) {
				if (password == null) {
					throw new IOException("PEM is encrypted, but no password was specified");
				}

				TypesReader optionsReader = new TypesReader(kdfoptions);
				byte[] salt = optionsReader.readByteString();
				int rounds = optionsReader.readUINT32();
				dataBytes = decryptData(dataBytes, password.getBytes(StandardCharsets.UTF_8), salt, rounds, ciphername);
			} else if (!"none".equals(ciphername) || !"none".equals(kdfname)) {
				throw new IOException("encryption not supported");
			}

			TypesReader trEnc = new TypesReader(dataBytes);

			int checkInt1 = trEnc.readUINT32();
			int checkInt2 = trEnc.readUINT32();

			if (checkInt1 != checkInt2) {
				throw new IOException("Decryption failed when trying to read private keys");
			}

			String keyType = trEnc.readString();

			KeyPair keyPair;
			if (Ed25519Verify.ED25519_ID.equals(keyType)) {
				byte[] publicBytes = trEnc.readByteString();
				byte[] privateBytes = trEnc.readByteString();
				EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(Ed25519Verify.ED25519_CURVE_NAME);
				PrivateKey privKey = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(
						Arrays.copyOfRange(privateBytes, 0, 32), spec));
				PublicKey pubKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(publicBytes, spec));
				keyPair = new KeyPair(pubKey, privKey);
			} else if (keyType.startsWith("ecdsa-sha2-")) {
				String curveName = trEnc.readString();

				ECParameterSpec spec = ECDSASHA2Verify.getCurveForName(curveName);
				if (null == spec) {
					throw new IOException("Invalid curve name");
				}

				byte[] groupBytes = trEnc.readByteString();
				BigInteger privateKey = trEnc.readMPINT();

				ECPoint group = ECDSASHA2Verify.decodeECPoint(groupBytes, spec.getCurve());
				if (null == group) {
					throw new IOException("Invalid ECDSA group");
				}

				ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(group, spec);
				ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey, spec);
				keyPair = generateKeyPair("EC", privateKeySpec, publicKeySpec);
			} else if ("ssh-rsa".equals(keyType)) {
				BigInteger n = trEnc.readMPINT();
				BigInteger e = trEnc.readMPINT();
				BigInteger d = trEnc.readMPINT();

				BigInteger crtCoefficient = trEnc.readMPINT();
				BigInteger p = trEnc.readMPINT();

				RSAPrivateKeySpec privateKeySpec;
				if (null == p || null == crtCoefficient) {
					privateKeySpec = new RSAPrivateKeySpec(n, d);
				} else {
					BigInteger q = crtCoefficient.modInverse(p);
					BigInteger pE = d.mod(p.subtract(BigInteger.ONE));
					BigInteger qE = d.mod(q.subtract(BigInteger.ONE));
					privateKeySpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, pE, qE, crtCoefficient);

				}

				RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);

				keyPair = generateKeyPair("RSA", privateKeySpec, publicKeySpec);
			} else if ("ssh-dss".equals(keyType)) {
				BigInteger p = trEnc.readMPINT();
				BigInteger q = trEnc.readMPINT();
				BigInteger g = trEnc.readMPINT();
				BigInteger y = trEnc.readMPINT();
				BigInteger x = trEnc.readMPINT();

				DSAPrivateKeySpec privateKeySpec = new DSAPrivateKeySpec(x, p, q, g);
				DSAPublicKeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);

				keyPair = generateKeyPair("DSA", privateKeySpec, publicKeySpec);
			} else {
				throw new IOException("Unknown key type " + keyType);
			}

			byte[] comment = trEnc.readByteString();

			// Make sure the padding is correct first.
			int remaining = tr.remain();
			for (int i = 1; i <= remaining; i++) {
				if (i != tr.readByte()) {
					throw new IOException("Bad padding value on decrypted private keys");
				}
			}

			return keyPair;
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

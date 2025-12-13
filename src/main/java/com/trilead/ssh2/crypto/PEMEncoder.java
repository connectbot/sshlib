package com.trilead.ssh2.crypto;

import com.trilead.ssh2.crypto.cipher.AES;
import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.cipher.DES;
import com.trilead.ssh2.crypto.cipher.DESede;
import com.trilead.ssh2.signature.ECDSASHA2Verify;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.DigestException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Locale;

/**
 * PEM encoder for traditional private key formats (RSA, DSA, EC).
 * Creates PEM-encoded private keys with optional password-based encryption.
 *
 * @author Kenny Root
 */
public class PEMEncoder {

	public static final String DES_EDE3_CBC = "DES-EDE3-CBC";
	public static final String AES_128_CBC = "AES-128-CBC";
	public static final String AES_192_CBC = "AES-192-CBC";
	public static final String AES_256_CBC = "AES-256-CBC";
	public static final String DEFAULT_ENCRYPTION = AES_256_CBC;

	private static final int LINE_LENGTH = 64;

	/**
	 * Encode RSA private key to PEM format.
	 *
	 * @param privateKey RSA private key
	 * @param password password for encryption, or null for unencrypted
	 * @return PEM-encoded private key
	 * @throws IOException if encoding fails
	 */
	public static String encodeRSAPrivateKey(RSAPrivateCrtKey privateKey, String password) throws IOException {
		return encodeRSAPrivateKey(privateKey, password, DEFAULT_ENCRYPTION);
	}

	/**
	 * Encode RSA private key to PEM format with specified encryption algorithm.
	 *
	 * @param privateKey RSA private key
	 * @param password password for encryption, or null for unencrypted
	 * @param algorithm encryption algorithm (e.g., AES_256_CBC)
	 * @return PEM-encoded private key
	 * @throws IOException if encoding fails
	 */
	public static String encodeRSAPrivateKey(RSAPrivateCrtKey privateKey, String password, String algorithm)
			throws IOException {
		SimpleDERWriter writer = new SimpleDERWriter();
		writer.writeInt(BigInteger.ZERO);
		writer.writeInt(privateKey.getModulus());
		writer.writeInt(privateKey.getPublicExponent());
		writer.writeInt(privateKey.getPrivateExponent());
		writer.writeInt(privateKey.getPrimeP());
		writer.writeInt(privateKey.getPrimeQ());
		writer.writeInt(privateKey.getPrimeExponentP());
		writer.writeInt(privateKey.getPrimeExponentQ());
		writer.writeInt(privateKey.getCrtCoefficient());

		SimpleDERWriter outer = new SimpleDERWriter();
		outer.writeSequence(writer.getBytes());

		return formatPEM("RSA PRIVATE KEY", outer.getBytes(), password, algorithm);
	}

	/**
	 * Encode DSA private key to PEM format.
	 *
	 * @param privateKey DSA private key
	 * @param password password for encryption, or null for unencrypted
	 * @return PEM-encoded private key
	 * @throws IOException if encoding fails
	 */
	public static String encodeDSAPrivateKey(DSAPrivateKey privateKey, String password) throws IOException {
		return encodeDSAPrivateKey(privateKey, password, DEFAULT_ENCRYPTION);
	}

	/**
	 * Encode DSA private key to PEM format with specified encryption algorithm.
	 *
	 * @param privateKey DSA private key
	 * @param password password for encryption, or null for unencrypted
	 * @param algorithm encryption algorithm
	 * @return PEM-encoded private key
	 * @throws IOException if encoding fails
	 */
	public static String encodeDSAPrivateKey(DSAPrivateKey privateKey, String password, String algorithm)
			throws IOException {
		BigInteger p = privateKey.getParams().getP();
		BigInteger q = privateKey.getParams().getQ();
		BigInteger g = privateKey.getParams().getG();
		BigInteger x = privateKey.getX();
		BigInteger y = g.modPow(x, p);

		SimpleDERWriter writer = new SimpleDERWriter();
		writer.writeInt(BigInteger.ZERO);
		writer.writeInt(p);
		writer.writeInt(q);
		writer.writeInt(g);
		writer.writeInt(y);
		writer.writeInt(x);

		SimpleDERWriter outer = new SimpleDERWriter();
		outer.writeSequence(writer.getBytes());

		return formatPEM("DSA PRIVATE KEY", outer.getBytes(), password, algorithm);
	}

	/**
	 * Encode EC private key to PEM format.
	 *
	 * @param privateKey EC private key
	 * @param password password for encryption, or null for unencrypted
	 * @return PEM-encoded private key
	 * @throws IOException if encoding fails
	 */
	public static String encodeECPrivateKey(ECPrivateKey privateKey, String password) throws IOException {
		return encodeECPrivateKey(privateKey, password, DEFAULT_ENCRYPTION);
	}

	/**
	 * Encode EC private key to PEM format with specified encryption algorithm.
	 *
	 * @param privateKey EC private key
	 * @param password password for encryption, or null for unencrypted
	 * @param algorithm encryption algorithm
	 * @return PEM-encoded private key
	 * @throws IOException if encoding fails
	 */
	public static String encodeECPrivateKey(ECPrivateKey privateKey, String password, String algorithm)
			throws IOException {
		BigInteger s = privateKey.getS();

		ECDSASHA2Verify verifier = ECDSASHA2Verify.getVerifierForKey(privateKey);
		if (verifier == null) {
			throw new IOException("Unsupported EC curve");
		}

		int fieldSize = privateKey.getParams().getCurve().getField().getFieldSize();
		int keyLength = (fieldSize + 7) / 8;
		byte[] privateBytes = toByteArray(s, keyLength);

		String curveOid = verifier.getOid();

		ECPoint publicPoint = derivePublicPoint(privateKey);

		byte[] publicBytes = ECDSASHA2Verify.encodeECPoint(
				publicPoint,
				privateKey.getParams().getCurve());

		SimpleDERWriter oidWriter = new SimpleDERWriter();
		oidWriter.writeOid(curveOid);

		SimpleDERWriter publicWriter = new SimpleDERWriter();
		publicWriter.writeBitString(publicBytes);

		SimpleDERWriter writer = new SimpleDERWriter();
		writer.writeInt(BigInteger.ONE);
		writer.writeOctetString(privateBytes);
		writer.writeByte((byte) 0xa0);
		writer.writeLength(oidWriter.getBytes().length);
		writer.writeBytes(oidWriter.getBytes());
		writer.writeByte((byte) 0xa1);
		writer.writeLength(publicWriter.getBytes().length);
		writer.writeBytes(publicWriter.getBytes());

		SimpleDERWriter outer = new SimpleDERWriter();
		outer.writeSequence(writer.getBytes());

		return formatPEM("EC PRIVATE KEY", outer.getBytes(), password, algorithm);
	}

	/**
	 * Encode private key to PEM format with auto-detected key type.
	 *
	 * @param privateKey private key (RSA, DSA, or EC)
	 * @param password password for encryption, or null for unencrypted
	 * @return PEM-encoded private key
	 * @throws IOException if encoding fails
	 * @throws InvalidKeyException if key type is not supported
	 */
	public static String encodePrivateKey(PrivateKey privateKey, String password)
			throws IOException, InvalidKeyException {
		return encodePrivateKey(privateKey, password, DEFAULT_ENCRYPTION);
	}

	/**
	 * Encode private key to PEM format with auto-detected key type and specified algorithm.
	 *
	 * @param privateKey private key (RSA, DSA, or EC)
	 * @param password password for encryption, or null for unencrypted
	 * @param algorithm encryption algorithm
	 * @return PEM-encoded private key
	 * @throws IOException if encoding fails
	 * @throws InvalidKeyException if key type is not supported
	 */
	public static String encodePrivateKey(PrivateKey privateKey, String password, String algorithm)
			throws IOException, InvalidKeyException {
		if (privateKey instanceof RSAPrivateCrtKey) {
			return encodeRSAPrivateKey((RSAPrivateCrtKey) privateKey, password, algorithm);
		} else if (privateKey instanceof DSAPrivateKey) {
			return encodeDSAPrivateKey((DSAPrivateKey) privateKey, password, algorithm);
		} else if (privateKey instanceof ECPrivateKey) {
			return encodeECPrivateKey((ECPrivateKey) privateKey, password, algorithm);
		} else {
			throw new InvalidKeyException("Unsupported key type: " + privateKey.getClass().getName());
		}
	}

	private static String formatPEM(String type, byte[] data, String password, String algorithm) throws IOException {
		byte[] encodedData = data;

		StringBuilder sb = new StringBuilder();
		sb.append("-----BEGIN ").append(type).append("-----\n");

		if (password != null && !password.isEmpty()) {
			byte[] passwordBytes;
			try {
				passwordBytes = password.getBytes("ISO-8859-1");
			} catch (UnsupportedEncodingException e) {
				passwordBytes = password.getBytes();
			}

			int blockSize = getBlockSize(algorithm);

			byte[] salt = new byte[blockSize];
			SecureRandom random = new SecureRandom();
			random.nextBytes(salt);

			encodedData = encryptData(data, passwordBytes, salt, algorithm);

			sb.append("Proc-Type: 4,ENCRYPTED\n");
			sb.append("DEK-Info: ").append(algorithm).append(",");
			sb.append(byteArrayToHex(salt).toUpperCase()).append("\n\n");
		}

		String base64 = new String(Base64.encode(encodedData));
		for (int i = 0; i < base64.length(); i += LINE_LENGTH) {
			int end = Math.min(i + LINE_LENGTH, base64.length());
			sb.append(base64.substring(i, end)).append("\n");
		}

		sb.append("-----END ").append(type).append("-----\n");

		return sb.toString();
	}

	private static BlockCipher getCipher(String algo) throws IOException {
		String algoLower = algo.toLowerCase(Locale.US);
		if (algoLower.equals("des-ede3-cbc")) {
			return new DESede.CBC();
		} else if (algoLower.equals("des-cbc")) {
			return new DES.CBC();
		} else if (algoLower.equals("aes-128-cbc")) {
			return new AES.CBC();
		} else if (algoLower.equals("aes-192-cbc")) {
			return new AES.CBC();
		} else if (algoLower.equals("aes-256-cbc")) {
			return new AES.CBC();
		} else {
			throw new IOException("Unsupported encryption algorithm: " + algo);
		}
	}

	private static int getKeySize(String algo) throws IOException {
		String algoLower = algo.toLowerCase(Locale.US);
		if (algoLower.equals("des-ede3-cbc")) {
			return 24;
		} else if (algoLower.equals("des-cbc")) {
			return 8;
		} else if (algoLower.equals("aes-128-cbc")) {
			return 16;
		} else if (algoLower.equals("aes-192-cbc")) {
			return 24;
		} else if (algoLower.equals("aes-256-cbc")) {
			return 32;
		} else {
			throw new IOException("Unsupported encryption algorithm: " + algo);
		}
	}

	private static int getBlockSize(String algo) throws IOException {
		String algoLower = algo.toLowerCase(Locale.US);
		if (algoLower.equals("des-ede3-cbc") || algoLower.equals("des-cbc")) {
			return 8;
		} else if (algoLower.startsWith("aes-")) {
			return 16;
		} else {
			throw new IOException("Unsupported encryption algorithm: " + algo);
		}
	}

	private static byte[] encryptData(byte[] data, byte[] password, byte[] salt, String algo) throws IOException {
		BlockCipher bc = getCipher(algo);
		int keySize = getKeySize(algo);

		byte[] key = generateKeyFromPasswordSaltWithMD5(password, salt, keySize);

		bc.init(true, key, salt);

		byte[] paddedData = addPKCS7Padding(data, bc.getBlockSize());

		byte[] encrypted = new byte[paddedData.length];
		for (int i = 0; i < paddedData.length / bc.getBlockSize(); i++) {
			bc.transformBlock(paddedData, i * bc.getBlockSize(), encrypted, i * bc.getBlockSize());
		}

		return encrypted;
	}

	private static byte[] generateKeyFromPasswordSaltWithMD5(byte[] password, byte[] salt, int keyLen)
			throws IOException {
		if (salt.length < 8) {
			throw new IllegalArgumentException("Salt needs to be at least 8 bytes for key generation.");
		}

		MessageDigest md5;
		try {
			md5 = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("JVM does not support MD5", e);
		}

		byte[] key = new byte[keyLen];
		byte[] tmp = new byte[md5.getDigestLength()];

		while (true) {
			md5.update(password, 0, password.length);
			md5.update(salt, 0, 8);

			int copy = (keyLen < tmp.length) ? keyLen : tmp.length;

			try {
				md5.digest(tmp, 0, tmp.length);
			} catch (DigestException e) {
				throw new IOException("could not digest password", e);
			}

			System.arraycopy(tmp, 0, key, key.length - keyLen, copy);

			keyLen -= copy;

			if (keyLen == 0) {
				return key;
			}

			md5.update(tmp, 0, tmp.length);
		}
	}

	private static byte[] addPKCS7Padding(byte[] data, int blockSize) {
		int paddingLength = blockSize - (data.length % blockSize);
		byte[] padded = new byte[data.length + paddingLength];
		System.arraycopy(data, 0, padded, 0, data.length);

		for (int i = data.length; i < padded.length; i++) {
			padded[i] = (byte) paddingLength;
		}

		return padded;
	}

	private static String byteArrayToHex(byte[] bytes) {
		StringBuilder hex = new StringBuilder();
		for (byte b : bytes) {
			hex.append(String.format("%02x", b & 0xff));
		}
		return hex.toString();
	}

	private static ECPoint derivePublicPoint(ECPrivateKey privateKey) throws IOException {
		BigInteger s = privateKey.getS();
		ECPoint generator = privateKey.getParams().getGenerator();
		return performScalarMultiplication(generator, s, privateKey.getParams());
	}

	private static ECPoint performScalarMultiplication(ECPoint point, BigInteger k, ECParameterSpec params) {
		if (k.equals(BigInteger.ZERO) || k.signum() < 0) {
			return ECPoint.POINT_INFINITY;
		}

		ECPoint result = ECPoint.POINT_INFINITY;
		ECPoint addend = point;

		while (k.signum() > 0) {
			if (k.testBit(0)) {
				result = addECPoints(result, addend, params);
			}
			addend = doubleECPoint(addend, params);
			k = k.shiftRight(1);
		}

		return result;
	}

	private static ECPoint addECPoints(ECPoint p1, ECPoint p2, ECParameterSpec params) {
		if (p1.equals(ECPoint.POINT_INFINITY)) {
			return p2;
		}
		if (p2.equals(ECPoint.POINT_INFINITY)) {
			return p1;
		}

		BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();

		BigInteger x1 = p1.getAffineX();
		BigInteger y1 = p1.getAffineY();
		BigInteger x2 = p2.getAffineX();
		BigInteger y2 = p2.getAffineY();

		if (x1.equals(x2)) {
			if (y1.equals(y2)) {
				return doubleECPoint(p1, params);
			}
			return ECPoint.POINT_INFINITY;
		}

		BigInteger slope = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(p)).mod(p);
		BigInteger x3 = slope.multiply(slope).subtract(x1).subtract(x2).mod(p);
		BigInteger y3 = slope.multiply(x1.subtract(x3)).subtract(y1).mod(p);

		return new ECPoint(x3, y3);
	}

	private static ECPoint doubleECPoint(ECPoint point, ECParameterSpec params) {
		if (point.equals(ECPoint.POINT_INFINITY)) {
			return point;
		}

		BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();
		BigInteger a = params.getCurve().getA();

		BigInteger x = point.getAffineX();
		BigInteger y = point.getAffineY();

		BigInteger slope = x.multiply(x).multiply(BigInteger.valueOf(3))
				.add(a)
				.multiply(y.multiply(BigInteger.TWO).modInverse(p))
				.mod(p);

		BigInteger x3 = slope.multiply(slope).subtract(x).subtract(x).mod(p);
		BigInteger y3 = slope.multiply(x.subtract(x3)).subtract(y).mod(p);

		return new ECPoint(x3, y3);
	}

	private static byte[] toByteArray(BigInteger value, int length) {
		byte[] bytes = value.toByteArray();

		if (bytes.length == length) {
			return bytes;
		}

		if (bytes.length > length) {
			if (bytes[0] == 0 && bytes.length == length + 1) {
				byte[] result = new byte[length];
				System.arraycopy(bytes, 1, result, 0, length);
				return result;
			}
			throw new IllegalArgumentException("Value too large for specified length");
		}

		byte[] result = new byte[length];
		System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
		return result;
	}
}

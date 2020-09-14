/*
 * Copyright 2014 Kenny Root
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * a.) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * b.) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * c.) Neither the name of Trilead nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.trilead.ssh2.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import com.trilead.ssh2.crypto.SimpleDERReader;
import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;

/**
 * @author Kenny Root
 *
 */
public abstract class ECDSASHA2Verify implements SSHSignature {
	private static final Logger log = Logger.getLogger(ECDSASHA2Verify.class);

	public static final String ECDSA_SHA2_PREFIX = "ecdsa-sha2-";

	@Override
	public abstract String getKeyFormat();

	@Override
	public PublicKey decodePublicKey(byte[] key) throws IOException {
		TypesReader tr = new TypesReader(key);

		String key_format = tr.readString();

		if (!key_format.startsWith(ECDSA_SHA2_PREFIX))
			throw new IllegalArgumentException("This is not an ECDSA public key");

		String curveName = tr.readString();
		byte[] groupBytes = tr.readByteString();

		if (tr.remain() != 0)
			throw new IOException("Padding in ECDSA public key!");

		if (!key_format.equals(getKeyFormat())) {
			throw new IOException("Key format is inconsistent with curve name: " + key_format
					+ " != " + curveName);
		}

		ECParameterSpec params = getParameterSpec();
		if (params == null) {
			throw new IOException("Curve is not supported: " + curveName);
		}

		ECPoint group = decodeECPoint(groupBytes);
		if (group == null) {
			throw new IOException("Invalid ECDSA group");
		}

		KeySpec keySpec = new ECPublicKeySpec(group, params);

		try {
			KeyFactory kf = KeyFactory.getInstance("EC");
			return kf.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException nsae) {
			throw new IOException("No EC KeyFactory available", nsae);
		}
	}

	public abstract ECParameterSpec getParameterSpec();

	@Override
	public byte[] encodePublicKey(PublicKey key) {
		ECPublicKey ecPublicKey = (ECPublicKey) key;
		TypesWriter tw = new TypesWriter();

		String keyFormat = ECDSA_SHA2_PREFIX + getCurveName();

		tw.writeString(keyFormat);

		tw.writeString(getCurveName());

		byte[] encoded = encodeECPoint(ecPublicKey.getW(), ecPublicKey.getParams().getCurve());
		tw.writeString(encoded, 0, encoded.length);

		return tw.getBytes();
	}

	public static ECDSASHA2Verify getVerifierForKey(ECKey key) {
		switch (key.getParams().getCurve().getField().getFieldSize()) {
			case 256:
				return ECDSASHA2NISTP256Verify.get();
			case 384:
				return ECDSASHA2NISTP384Verify.get();
			case 521:
				return ECDSASHA2NISTP521Verify.get();
			default:
				return null;
		}
	}

	public static String getSshKeyType(ECKey ecKey) {
		ECDSASHA2Verify verifier = getVerifierForKey(ecKey);
		if (verifier == null)
			return null;
		return verifier.getKeyFormat();
	}

	public abstract String getCurveName();

	public abstract String getOid();

	public static int getCurveSize(ECParameterSpec params) {
		return params.getCurve().getField().getFieldSize();
	}

	public static ECDSASHA2Verify getVerifierForOID(String oid) {
		if (oid == null) {
			return null;
		}

		if (oid.equals(ECDSASHA2NISTP256Verify.get().getOid())) {
			return ECDSASHA2NISTP256Verify.get();
		} else if (oid.equals(ECDSASHA2NISTP384Verify.get().getOid())) {
			return ECDSASHA2NISTP384Verify.get();
		} else if (oid.equals(ECDSASHA2NISTP521Verify.get().getOid())) {
			return ECDSASHA2NISTP521Verify.get();
		} else {
			return null;
		}
	}

	private byte[] decodeSSHECDSASignature(byte[] sig) throws IOException {
		byte[] rsArray;

		TypesReader tr = new TypesReader(sig);

		String sig_format = tr.readString();
		if (!sig_format.equals(getKeyFormat())) {
			throw new IOException("Unsupported format: " + sig_format);
		}

		rsArray = tr.readByteString();

		if (tr.remain() != 0)
			throw new IOException("Padding in ECDSA signature!");

		byte[] rArray;
		byte[] sArray;
		{
			TypesReader rsReader = new TypesReader(rsArray);
			rArray = rsReader.readMPINT().toByteArray();
			sArray = rsReader.readMPINT().toByteArray();
		}

		int first = rArray.length;
		int second = sArray.length;

		/* We can't have the high bit set, so add an extra zero at the beginning if so. */
		if ((rArray[0] & 0x80) != 0) {
			first++;
		}
		if ((sArray[0] & 0x80) != 0) {
			second++;
		}

		/* Calculate total output length */
		ByteArrayOutputStream os = new ByteArrayOutputStream(6 + first + second);

		/* ASN.1 SEQUENCE tag */
		os.write(0x30);

		/* Size of SEQUENCE */
		writeLength(4 + first + second, os);

		/* ASN.1 INTEGER tag */
		os.write(0x02);

		/* "r" INTEGER length */
		writeLength(first, os);

		/* Copy in the "r" INTEGER */
		if (first != rArray.length) {
			os.write(0x00);
		}
		os.write(rArray);

		/* ASN.1 INTEGER tag */
		os.write(0x02);

		/* "s" INTEGER length */
		writeLength(second, os);

		/* Copy in the "s" INTEGER */
		if (second != sArray.length) {
			os.write(0x00);
		}
		os.write(sArray);

		return os.toByteArray();
	}

	private static void writeLength(int length, OutputStream os) throws IOException {
		if (length <= 0x7F) {
			os.write(length);
			return;
		}

		int numOctets = 0;
		int lenCopy = length;
		while (lenCopy != 0) {
			lenCopy >>>= 8;
			numOctets++;
		}

		os.write(0x80 | numOctets);

		for (int i = (numOctets - 1) * 8; i >= 0; i -= 8) {
			os.write((byte) (length >> i));
		}
	}

	private byte[] encodeSSHECDSASignature(byte[] sig) throws IOException
	{
		TypesWriter tw = new TypesWriter();

		tw.writeString(getKeyFormat());

		/*
		 * This is a signature in ASN.1 DER format. It should look like:
		 *  0x30 <len>
		 *      0x02 <len> <data[len]>
		 *      0x02 <len> <data[len]>
		 */

		SimpleDERReader reader = new SimpleDERReader(sig);
		reader.resetInput(reader.readSequenceAsByteArray());

		BigInteger r = reader.readInt();
		BigInteger s = reader.readInt();

		// Write the <r,s> to its own types writer.
		TypesWriter rsWriter = new TypesWriter();
		rsWriter.writeMPInt(r);
		rsWriter.writeMPInt(s);
		byte[] encoded = rsWriter.getBytes();
		tw.writeString(encoded, 0, encoded.length);

		return tw.getBytes();
	}

	@Override
	public byte[] generateSignature(byte[] message, PrivateKey pk, SecureRandom secureRandom) throws IOException
	{
		final String algo = getSignatureAlgorithm();

		try {
			Signature s = Signature.getInstance(algo);
			s.initSign(pk, secureRandom);
			s.update(message);
			return encodeSSHECDSASignature(s.sign());
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new IOException(e);
		}
	}

	protected abstract String getSignatureAlgorithm();

	@Override
	public boolean verifySignature(byte[] message, byte[] sshSig, PublicKey pk) throws IOException
	{
		byte[] javaSig = decodeSSHECDSASignature(sshSig);
		try {
			Signature s = Signature.getInstance(getSignatureAlgorithm());
			s.initVerify(pk);
			s.update(message);
			return s.verify(javaSig);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IOException("No such algorithm", e);
		} catch (SignatureException e) {
			throw new IOException(e);
		}
	}

	public static String getDigestAlgorithmForParams(ECKey key) {
		ECDSASHA2Verify verifier = getVerifierForKey(key);
		if (verifier == null)
			return null;
		return verifier.getDigestAlgorithm();
	}

	protected abstract String getDigestAlgorithm();

	/**
	 * Decode an OctetString to EllipticCurvePoint according to SECG 2.3.4
	 */
	public ECPoint decodeECPoint(byte[] M) {
		if (M.length == 0) {
			return null;
		}

		// M has len 2 ceil(log_2(q)/8) + 1 ?
		EllipticCurve curve = getParameterSpec().getCurve();
		int elementSize = (curve.getField().getFieldSize() + 7) / 8;
		if (M.length != 2 * elementSize + 1) {
			return null;
		}

		// step 3.2
		if (M[0] != 0x04) {
			return null;
		}

		// Step 3.3
		byte[] xp = new byte[elementSize];
		System.arraycopy(M, 1, xp, 0, elementSize);

		// Step 3.4
		byte[] yp = new byte[elementSize];
		System.arraycopy(M, 1 + elementSize, yp, 0, elementSize);

		ECPoint P = new ECPoint(new BigInteger(1, xp), new BigInteger(1, yp));

		// TODO check point 3.5

		// Step 3.6
		return P;
	}

	/**
	 * Encode EllipticCurvePoint to an OctetString
	 */
	public static byte[] encodeECPoint(ECPoint group, EllipticCurve curve)
	{
		// M has len 2 ceil(log_2(q)/8) + 1 ?
		int elementSize = (curve.getField().getFieldSize() + 7) / 8;
		byte[] M = new byte[2 * elementSize + 1];

		// Uncompressed format
		M[0] = 0x04;

		{
			byte[] affineX = removeLeadingZeroes(group.getAffineX().toByteArray());
			System.arraycopy(affineX, 0, M, 1 + elementSize - affineX.length, affineX.length);
		}

		{
			byte[] affineY = removeLeadingZeroes(group.getAffineY().toByteArray());
			System.arraycopy(affineY, 0, M, 1 + elementSize + elementSize - affineY.length,
							affineY.length);
		}

		return M;
	}

	private static byte[] removeLeadingZeroes(byte[] input) {
		if (input[0] != 0x00) {
			return input;
		}

		int pos = 1;
		while (pos < input.length - 1 && input[pos] == 0x00) {
			pos++;
		}

		byte[] output = new byte[input.length - pos];
		System.arraycopy(input, pos, output, 0, output.length);
		return output;
	}

	public static class ECDSASHA2NISTP256Verify extends ECDSASHA2Verify {
		private static final String NISTP256 = "nistp256";
		private static final String NISTP256_OID = "1.2.840.10045.3.1.7";
		private static final String KEY_FORMAT = ECDSA_SHA2_PREFIX + NISTP256;

		@Override
		public String getCurveName() {
			return NISTP256;
		}

		@Override
		public String getOid() {
			return NISTP256_OID;
		}

		@Override
		protected String getSignatureAlgorithm() {
			return "SHA256withECDSA";
		}

		@Override
		protected String getDigestAlgorithm() {
			return "SHA-256";
		}

		@Override
		public String getKeyFormat() {
			return KEY_FORMAT;
		}

		@Override
		public ECParameterSpec getParameterSpec() {
			return nistp256;
		}

		private static class InstanceHolder {
			private static final ECDSASHA2NISTP256Verify sInstance = new ECDSASHA2NISTP256Verify();
		}

		private ECDSASHA2NISTP256Verify() {
		}

		public static ECDSASHA2NISTP256Verify get() {
			return ECDSASHA2NISTP256Verify.InstanceHolder.sInstance;
		}

		public static ECParameterSpec nistp256 = new ECParameterSpec(
			new EllipticCurve(
				new ECFieldFp(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
				new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
				new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)),
			new ECPoint(new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
				new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)),
			new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
			1);
	}

	public static class ECDSASHA2NISTP384Verify extends ECDSASHA2Verify {
		private static final String NISTP384 = "nistp384";
		private static final String NISTP384_OID = "1.3.132.0.34";
		private static final String KEY_FORMAT = ECDSA_SHA2_PREFIX + NISTP384;

		@Override
		public String getKeyFormat() {
			return KEY_FORMAT;
		}

		private static class InstanceHolder {
			private static final ECDSASHA2NISTP384Verify sInstance = new ECDSASHA2NISTP384Verify();
		}

		private ECDSASHA2NISTP384Verify() {
		}

		public static ECDSASHA2NISTP384Verify get() {
			return ECDSASHA2NISTP384Verify.InstanceHolder.sInstance;
		}

		@Override
		public ECParameterSpec getParameterSpec() {
			return nistp384;
		}

		@Override
		public String getCurveName() {
			return NISTP384;
		}

		@Override
		public String getOid() {
			return NISTP384_OID;
		}

		@Override
		protected String getSignatureAlgorithm() {
			return "SHA384withECDSA";
		}

		@Override
		protected String getDigestAlgorithm() {
			return "SHA-384";
		}

		public static ECParameterSpec nistp384 = new ECParameterSpec(
			new EllipticCurve(
				new ECFieldFp(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16)),
				new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16),
				new BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16)),
			new ECPoint(new BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16),
				new BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16)),
			new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
			1);
	}

	public static class ECDSASHA2NISTP521Verify extends ECDSASHA2Verify {
		private static final String NISTP521 = "nistp521";
		private static final String NISTP521_OID = "1.3.132.0.35";
		private static final String KEY_FORMAT = ECDSA_SHA2_PREFIX + NISTP521;

		@Override
		public String getKeyFormat() {
			return KEY_FORMAT;
		}

		@Override
		public ECParameterSpec getParameterSpec() {
			return nistp521;
		}

		@Override
		public String getCurveName() {
			return NISTP521;
		}

		@Override
		public String getOid() {
			return NISTP521_OID;
		}

		@Override
		protected String getSignatureAlgorithm() {
			return "SHA512withECDSA";
		}

		@Override
		protected String getDigestAlgorithm() {
			return "SHA-512";
		}

		private static class InstanceHolder {
			private static final ECDSASHA2NISTP521Verify sInstance = new ECDSASHA2NISTP521Verify();
		}

		private ECDSASHA2NISTP521Verify() {
		}

		public static ECDSASHA2NISTP521Verify get() {
			return ECDSASHA2NISTP521Verify.InstanceHolder.sInstance;
		}

		public static ECParameterSpec nistp521 = new ECParameterSpec(
			new EllipticCurve(
				new ECFieldFp(new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)),
				new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16),
				new BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16)),
			new ECPoint(new BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
				new BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16)),
			new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
			1);
	}
}

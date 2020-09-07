package com.trilead.ssh2.crypto.dh;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;

import com.trilead.ssh2.signature.ECDSASHA2Verify;

/**
 * @author kenny
 *
 */
public class EcDhExchange extends GenericDhExchange {
	private ECPrivateKey clientPrivate;
	private ECPublicKey clientPublic;
	private ECPublicKey serverPublic;

	@Override
	public void init(String name) throws IOException {
		final ECParameterSpec spec;

		if ("ecdh-sha2-nistp256".equals(name)) {
			spec = ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get().getParameterSpec();
		} else if ("ecdh-sha2-nistp384".equals(name)) {
			spec = ECDSASHA2Verify.ECDSASHA2NISTP384Verify.get().getParameterSpec();
		} else if ("ecdh-sha2-nistp521".equals(name)) {
			spec = ECDSASHA2Verify.ECDSASHA2NISTP521Verify.get().getParameterSpec();
		} else {
			throw new IllegalArgumentException("Unknown EC curve " + name);
		}

		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("EC");
			kpg.initialize(spec);
			KeyPair pair = kpg.generateKeyPair();
			clientPrivate = (ECPrivateKey) pair.getPrivate();
			clientPublic = (ECPublicKey) pair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("No DH keypair generator", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IOException("Invalid DH parameters", e);
		}
	}

	@Override
	public byte[] getE() {
		return ECDSASHA2Verify.encodeECPoint(clientPublic.getW(), clientPublic.getParams()
				.getCurve());
	}

	@Override
	protected byte[] getServerE() {
		return ECDSASHA2Verify.encodeECPoint(serverPublic.getW(), serverPublic.getParams()
				.getCurve());
	}

	@Override
	public void setF(byte[] f) throws IOException {

		if (clientPublic == null)
			throw new IllegalStateException("DhDsaExchange not initialized!");

		final KeyAgreement ka;
		try {
			KeyFactory kf = KeyFactory.getInstance("EC");
			ECDSASHA2Verify verifier = ECDSASHA2Verify.getVerifierForKey(clientPublic);
			if (verifier == null) {
				throw new IOException("No such EC group");
			}

			ECPoint serverPoint = verifier.decodeECPoint(f);
			ECParameterSpec params = verifier.getParameterSpec();
			this.serverPublic = (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(serverPoint,
																					params));

			ka = KeyAgreement.getInstance("ECDH");
			ka.init(clientPrivate);
			ka.doPhase(serverPublic, true);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("No ECDH key agreement method", e);
		} catch (InvalidKeyException | InvalidKeySpecException e) {
			throw new IOException("Invalid ECDH key", e);
		}

		sharedSecret = new BigInteger(1, ka.generateSecret());
	}

	@Override
	public String getHashAlgo() {
		return ECDSASHA2Verify.getDigestAlgorithmForParams(clientPublic);
	}
}

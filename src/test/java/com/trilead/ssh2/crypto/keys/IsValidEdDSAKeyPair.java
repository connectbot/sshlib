package com.trilead.ssh2.crypto.keys;

import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class IsValidEdDSAKeyPair extends TypeSafeMatcher<KeyPair> {
	@Override
	protected boolean matchesSafely(KeyPair item) {
		PrivateKey privKey = item.getPrivate();
		PublicKey pubKey = item.getPublic();
		if (!(privKey instanceof Ed25519PrivateKey) || !(pubKey instanceof Ed25519PublicKey)) {
			return false;
		}

		Ed25519PrivateKey edPriv = (Ed25519PrivateKey) privKey;
		Ed25519PublicKey edPub = (Ed25519PublicKey) pubKey;

		try {
			byte[] signature = new Ed25519Sign(edPriv.getSeed()).sign(new byte[128]);
			new Ed25519Verify(edPub.getAbyte()).verify(signature, new byte[128]);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	@Override
	public void describeTo(Description description) {
		description.appendText("is valid EdDSA key pair");
	}

	public static Matcher<KeyPair> isValidEdDSAKeyPair() {
		return new IsValidEdDSAKeyPair();
	}
}

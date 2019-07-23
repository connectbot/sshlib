package com.trilead.ssh2;

import com.trilead.ssh2.signature.Ed25519Verify;

import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class KnownHostsTest {

	@Test
	public void supportsExpectedHashAndKeys()
		throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {

		KnownHosts obj = new KnownHosts();
		Method privateMethod = KnownHosts.class.getDeclaredMethod(
			"rawFingerPrint", String.class, String.class, byte[].class);
		privateMethod.setAccessible(true);
		privateMethod.invoke(obj, "md5", "ecdsa-sha2-", new byte[0]);
		privateMethod.invoke(obj, "md5", Ed25519Verify.ED25519_ID, new byte[0]);
		privateMethod.invoke(obj, "md5", "ssh-rsa", new byte[0]);
		privateMethod.invoke(obj, "md5", "ssh-dss", new byte[0]);
		privateMethod.invoke(obj, "md5", "rsa-sha2-256", new byte[0]);
		privateMethod.invoke(obj, "md5", "rsa-sha2-512", new byte[0]);

		privateMethod.invoke(obj, "sha1", "ecdsa-sha2-", new byte[0]);
		privateMethod.invoke(obj, "sha1", Ed25519Verify.ED25519_ID, new byte[0]);
		privateMethod.invoke(obj, "sha1", "ssh-rsa", new byte[0]);
		privateMethod.invoke(obj, "sha1", "ssh-dss", new byte[0]);
		privateMethod.invoke(obj, "sha1", "rsa-sha2-256", new byte[0]);
		privateMethod.invoke(obj, "sha1", "rsa-sha2-512", new byte[0]);
	}

	@Test
	public void failsInExpectedWayForUnsupportedHashAndKey()
		throws NoSuchMethodException, IllegalAccessException {

		KnownHosts obj = new KnownHosts();
		Method privateMethod = KnownHosts.class.getDeclaredMethod(
			"rawFingerPrint", String.class, String.class, byte[].class);
		privateMethod.setAccessible(true);
		try {
			privateMethod.invoke(obj, "UNSUPPORTED_HASH", "ssh-rsa", new byte[0]);
		} catch (InvocationTargetException e) {
			assertThat(e.getCause(), instanceOf(IllegalArgumentException.class));
			assertEquals(e.getCause().getMessage(), "Unknown hash type UNSUPPORTED_HASH");
		}
		try {
			privateMethod.invoke(obj, "sha1", "UNSUPPORTED_KEY", new byte[0]);
		} catch (InvocationTargetException e) {
			assertThat(e.getCause(), instanceOf(IllegalArgumentException.class));
			assertEquals(e.getCause().getMessage(), "Unknown key type UNSUPPORTED_KEY");
		}
		try {
			privateMethod.invoke(obj, "sha1", "ssh-rsa", null);
		} catch (InvocationTargetException e) {
			assertThat(e.getCause(), instanceOf(IllegalArgumentException.class));
			assertEquals(e.getCause().getMessage(), "hostkey is null");
		}
	}
}

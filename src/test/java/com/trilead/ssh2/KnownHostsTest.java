package com.trilead.ssh2;

import org.apache.commons.io.IOUtils;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.contains;

public class KnownHostsTest {
	private char[] getKnownHosts(String s) throws IOException {
		return IOUtils.toCharArray(getClass().getResourceAsStream(s), "UTF-8");
	}


	private static class KeyTypeMatcher extends TypeSafeMatcher<KnownHosts.KnownHostsEntry> {
		private final String keyType;

		public KeyTypeMatcher(String keyType) {
			this.keyType = keyType;
		}

		@Override
		protected boolean matchesSafely(KnownHosts.KnownHostsEntry item) {
			return item.key.getAlgorithm().equals(keyType);
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("has key of type='" + keyType + "'");
		}
	}

	public static Matcher<KnownHosts.KnownHostsEntry> hasKeyType(String keyType) {
		return new KeyTypeMatcher(keyType);
	}

	@Test
	public void initializeKnownHostsFile()
		throws IOException {

		KnownHosts obj = new KnownHosts();
		obj.addHostkeys(getKnownHosts("known_hosts"));
		assertThat(obj.publicKeys,
			contains(
				hasKeyType("RSA"),
				hasKeyType("EC"),
				hasKeyType("EdDSA"),
				hasKeyType("DSA"),
				hasKeyType("EC"),
				hasKeyType("RSA")));
	}

	@Test
	public void initializeInvalidHostKeyAlgo() {
		KnownHosts obj = new KnownHosts();
		try {
			obj.addHostkeys("host invalid-algo abc123".toCharArray());
			throw new Error("Did not throw Exception");
		} catch (IOException e) {
			assertThat(e.getMessage(), is("Unknown host key type (invalid-algo)"));
		}
		assertThat(obj.publicKeys.isEmpty(), is(true));
	}

	@Test
	public void initializeInvalidHostKey() throws IOException {
		KnownHosts obj = new KnownHosts();
		obj.addHostkeys("not-a-host-key".toCharArray());
		obj.addHostkeys("also not-a-host-key".toCharArray());
		assertThat(obj.publicKeys.isEmpty(), is(true));
	}

	@Test
	public void getPreferredServerHostkeyAlgorithmOrder_RsaKey() throws Exception {
		KnownHosts obj = new KnownHosts();
		obj.addHostkeys(getKnownHosts("known_hosts"));
		assertThat(obj.getPreferredServerHostkeyAlgorithmOrder("rsa"),
			arrayContaining(
				equalTo("rsa-sha2-512"),
				equalTo("rsa-sha2-256"),
				equalTo("ssh-rsa"),
				equalTo("ssh-ed25519"),
				equalTo("ecdsa-sha2-nistp256"),
				equalTo("ecdsa-sha2-nistp384"),
				equalTo("ecdsa-sha2-nistp521"),
				equalTo("ssh-dss")
			));
	}

	@Test
	public void getPreferredServerHostkeyAlgorithmOrder_DsaKey() throws Exception {
		KnownHosts obj = new KnownHosts();
		obj.addHostkeys(getKnownHosts("known_hosts"));
		assertThat(obj.getPreferredServerHostkeyAlgorithmOrder("dss"),
			arrayContaining(
				equalTo("ssh-dss"),
				equalTo("ssh-ed25519"),
				equalTo("ecdsa-sha2-nistp256"),
				equalTo("ecdsa-sha2-nistp384"),
				equalTo("ecdsa-sha2-nistp521"),
				equalTo("rsa-sha2-512"),
				equalTo("rsa-sha2-256"),
				equalTo("ssh-rsa")
			));
	}

	@Test
	public void getPreferredServerHostkeyAlgorithmOrder_EcdsaP256Key() throws Exception {
		KnownHosts obj = new KnownHosts();
		obj.addHostkeys(getKnownHosts("known_hosts"));
		assertThat(obj.getPreferredServerHostkeyAlgorithmOrder("ecdsap256"),
			arrayContaining(
				equalTo("ecdsa-sha2-nistp256"),
				equalTo("ssh-ed25519"),
				equalTo("ecdsa-sha2-nistp384"),
				equalTo("ecdsa-sha2-nistp521"),
				equalTo("rsa-sha2-512"),
				equalTo("rsa-sha2-256"),
				equalTo("ssh-rsa"),
				equalTo("ssh-dss")
			));
	}

	@Test
	public void getPreferredServerHostkeyAlgorithmOrder_Multiple() throws Exception {
		KnownHosts obj = new KnownHosts();
		obj.addHostkeys(getKnownHosts("known_hosts"));
		assertThat(obj.getPreferredServerHostkeyAlgorithmOrder("multiple"),
			arrayContaining(
				equalTo("ecdsa-sha2-nistp256"),
				equalTo("rsa-sha2-512"),
				equalTo("rsa-sha2-256"),
				equalTo("ssh-rsa"),
				equalTo("ssh-ed25519"),
				equalTo("ecdsa-sha2-nistp384"),
				equalTo("ecdsa-sha2-nistp521"),
				equalTo("ssh-dss")
			));	}

	@Test
	public void getPreferredServerHostkeyAlgorithmOrder_Unknown() throws Exception {
		KnownHosts obj = new KnownHosts();
		obj.addHostkeys(getKnownHosts("known_hosts"));
		assertThat(obj.getPreferredServerHostkeyAlgorithmOrder("unknown"),
			nullValue());
	}
}

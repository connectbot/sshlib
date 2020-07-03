package com.trilead.ssh2.crypto.keys;

import org.junit.Test;

import java.security.KeyPairGenerator;

import static com.trilead.ssh2.crypto.keys.IsValidEdDSAKeyPair.isValidEdDSAKeyPair;
import static org.hamcrest.MatcherAssert.assertThat;

public class EdDSAKeyPairGeneratorTest {
	@Test
	public void generatesValidKeys_noInitialize() throws Exception {
		EdDSAProvider p = new EdDSAProvider();
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", p);
		assertThat(kpg.generateKeyPair(), isValidEdDSAKeyPair());
	}

	@Test
	public void generatesValidKeys_withInitialize() throws Exception {
		EdDSAProvider p = new EdDSAProvider();
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA", p);
		kpg.initialize(256);
		assertThat(kpg.generateKeyPair(), isValidEdDSAKeyPair());
	}
}

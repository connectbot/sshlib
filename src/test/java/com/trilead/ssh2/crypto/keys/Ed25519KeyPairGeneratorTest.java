package com.trilead.ssh2.crypto.keys;

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;

import static com.trilead.ssh2.crypto.keys.IsValidEdDSAKeyPair.isValidEdDSAKeyPair;
import static org.hamcrest.MatcherAssert.assertThat;

public class Ed25519KeyPairGeneratorTest {
	@Test
	public void generatesValidKeys_noInitialize() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
		assertThat(kpg.generateKeyPair(), isValidEdDSAKeyPair());
	}

	@Test
	public void generatesValidKeys_withInitialize() throws Exception {
		Ed25519Provider p = new Ed25519Provider();
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", p);
		kpg.initialize(256);
		assertThat(kpg.generateKeyPair(), isValidEdDSAKeyPair());
	}
}

package com.trilead.ssh2;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.fail;

public class TestExtendedHostKeyVerifier extends ExtendedServerHostKeyVerifier {
	private final Logger logger = Logger.getLogger("TestHostKeyVerifier");
	private final KnownHosts knownHosts = new KnownHosts();

	@Override
	public List<String> getKnownKeyAlgorithmsForHost(String hostname, int port) {
		String[] algorithms = knownHosts.getPreferredServerHostkeyAlgorithmOrder(hostname);
		if (algorithms == null)
			return null;
		return Arrays.asList(algorithms);
	}

	@Override
	public void removeServerHostKey(String hostname, int port, String serverHostKeyAlgorithm, byte[] serverHostKey) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addServerHostKey(String hostname, int port, String keyAlgorithm, byte[] serverHostKey) {
		try {
			knownHosts.addHostkey(new String[]{hostname}, keyAlgorithm, serverHostKey);
		} catch (IOException e) {
			fail("Could not add host key");
		}
	}

	@Override
	public boolean verifyServerHostKey(String hostname, int port, String serverHostKeyAlgorithm, byte[] serverHostKey) throws Exception {
		try {
			int resultCode = knownHosts.verifyHostkey(hostname, serverHostKeyAlgorithm, serverHostKey);
			if (resultCode == KnownHosts.HOSTKEY_IS_OK) {
				logger.log(Level.INFO, "Verified host key of type " + serverHostKeyAlgorithm);
				return true;
			} else if (resultCode == KnownHosts.HOSTKEY_IS_NEW) {
				logger.log(Level.INFO, "New host key of type " + serverHostKeyAlgorithm);
				return true;
			}
		} catch (IOException e) {
			fail("Could not verify host key");
		}
		return false;
	}
}

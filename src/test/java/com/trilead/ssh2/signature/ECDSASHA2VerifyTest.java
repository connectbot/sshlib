package com.trilead.ssh2.signature;

import com.trilead.ssh2.crypto.PEMDecoder;
import org.junit.Test;


/**
 * Created by kenny on 12/25/15.
 */
public class ECDSASHA2VerifyTest {
	@Test
	public void decodeP521PEMKey() throws Exception {
		char[] pemKey = ("-----BEGIN EC PRIVATE KEY-----\n" +
			"MIHbAgEBBEGiLM/lkLGNRu6KdnQaWhWM/PBqR0ibIokEW4xa0Nv5O1TDBpiM+lus\n" +
			"wi8oM6qzWJbKf685J322VH3uYAs5oIYxJ6AHBgUrgQQAI6GBiQOBhgAEAK6P4X/5\n" +
			"n3hZssRG1x1jPNBTSFG79H36JkJHsCerPrsdjCNzfh/P5a87bCOor/My8un/JFly\n" +
			"H5mVXAO0t2YQq7qfAMCBawq2HfC+rfCikl5mrSYg6d0bshQ5ZIYAwU85VIK9kdjA\n" +
			"ImRIKkyB7MN7qqQUASFcYZLFwwdeRZw/0Yp7Ma/+\n" +
			"-----END EC PRIVATE KEY-----\n").toCharArray();
		PEMDecoder.decode(pemKey, null);
	}
}

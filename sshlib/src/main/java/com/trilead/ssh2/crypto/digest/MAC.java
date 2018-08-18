package com.trilead.ssh2.crypto.digest;

/**
 * Created by kenny on 2/12/17.
 */
public interface MAC {
	void initMac(int seq);
	void update(byte[] packetdata, int off, int len);
	void getMac(byte[] out, int off);
	int size();
	boolean isEncryptThenMac();
}


package com.trilead.ssh2.crypto;

import com.trilead.ssh2.compression.CompressionFactory;
import com.trilead.ssh2.crypto.cipher.BlockCipherFactory;
import com.trilead.ssh2.crypto.digest.MACs;
import com.trilead.ssh2.transport.KexManager;


/**
 * CryptoWishList.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: CryptoWishList.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */
public class CryptoWishList implements Cloneable
{
	public CryptoWishList() {
		kexAlgorithms = KexManager.getDefaultKexAlgorithmList();
		serverHostKeyAlgorithms = KexManager.getDefaultServerHostkeyAlgorithmList();
		c2s_enc_algos = BlockCipherFactory.getDefaultCipherList();
		s2c_enc_algos = BlockCipherFactory.getDefaultCipherList();
		c2s_mac_algos = MACs.getMacList();
		s2c_mac_algos = MACs.getMacList();
		c2s_comp_algos = CompressionFactory.getDefaultCompressorList();
		s2c_comp_algos = CompressionFactory.getDefaultCompressorList();
	}

	public CryptoWishList(CryptoWishList other) {
		kexAlgorithms = other.kexAlgorithms.clone();
		serverHostKeyAlgorithms = other.serverHostKeyAlgorithms.clone();
		c2s_enc_algos = other.c2s_enc_algos.clone();
		s2c_enc_algos = other.s2c_enc_algos.clone();
		c2s_mac_algos = other.c2s_mac_algos.clone();
		s2c_mac_algos = other.s2c_mac_algos.clone();
		c2s_comp_algos = other.c2s_comp_algos.clone();
		s2c_comp_algos = other.s2c_comp_algos.clone();
	}

	public String[] kexAlgorithms;
	public String[] serverHostKeyAlgorithms;
	public String[] c2s_enc_algos;
	public String[] s2c_enc_algos;
	public String[] c2s_mac_algos;
	public String[] s2c_mac_algos;
	public String[] c2s_comp_algos;
	public String[] s2c_comp_algos;

	@Override
	public CryptoWishList clone() {
		return new CryptoWishList(this);
	}
}

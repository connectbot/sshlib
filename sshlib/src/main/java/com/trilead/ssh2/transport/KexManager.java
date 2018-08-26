
package com.trilead.ssh2.transport;

import com.trilead.ssh2.signature.RSASHA256Verify;
import com.trilead.ssh2.signature.RSASHA512Verify;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.trilead.ssh2.ConnectionInfo;
import com.trilead.ssh2.DHGexParameters;
import com.trilead.ssh2.ExtendedServerHostKeyVerifier;
import com.trilead.ssh2.ServerHostKeyVerifier;
import com.trilead.ssh2.compression.CompressionFactory;
import com.trilead.ssh2.compression.ICompressor;
import com.trilead.ssh2.crypto.CryptoWishList;
import com.trilead.ssh2.crypto.KeyMaterial;
import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.cipher.BlockCipherFactory;
import com.trilead.ssh2.crypto.dh.Curve25519Exchange;
import com.trilead.ssh2.crypto.dh.DhGroupExchange;
import com.trilead.ssh2.crypto.dh.GenericDhExchange;
import com.trilead.ssh2.crypto.digest.HMAC;
import com.trilead.ssh2.crypto.digest.MAC;
import com.trilead.ssh2.crypto.digest.MACs;
import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.PacketKexDHInit;
import com.trilead.ssh2.packets.PacketKexDHReply;
import com.trilead.ssh2.packets.PacketKexDhGexGroup;
import com.trilead.ssh2.packets.PacketKexDhGexInit;
import com.trilead.ssh2.packets.PacketKexDhGexReply;
import com.trilead.ssh2.packets.PacketKexDhGexRequest;
import com.trilead.ssh2.packets.PacketKexDhGexRequestOld;
import com.trilead.ssh2.packets.PacketKexInit;
import com.trilead.ssh2.packets.PacketNewKeys;
import com.trilead.ssh2.packets.Packets;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;
import net.i2p.crypto.eddsa.EdDSAPublicKey;


/**
 * KexManager.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: KexManager.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */
public class KexManager
{
	private static final Logger log = Logger.getLogger(KexManager.class);

	private static final boolean supportsEc;
	static {
		KeyFactory keyFact;
		try {
			keyFact = KeyFactory.getInstance("EC");
		} catch (NoSuchAlgorithmException ignored) {
			keyFact = null;
			log.log(10, "Disabling EC support due to lack of KeyFactory");
		}
		supportsEc = keyFact != null;
	}

	private static final Set<String> HOSTKEY_ALGS = new LinkedHashSet<>();
	static {
		HOSTKEY_ALGS.add(Ed25519Verify.ED25519_ID);
		if (supportsEc) {
			HOSTKEY_ALGS.add("ecdsa-sha2-nistp256");
			HOSTKEY_ALGS.add("ecdsa-sha2-nistp384");
			HOSTKEY_ALGS.add("ecdsa-sha2-nistp521");
		}
		HOSTKEY_ALGS.add("ssh-rsa");
		HOSTKEY_ALGS.add("ssh-dss");
		HOSTKEY_ALGS.add("rsa-sha2-256");
		HOSTKEY_ALGS.add("rsa-sha2-512");
	}

	private static final Set<String> KEX_ALGS = new LinkedHashSet<>();
	static {
		KEX_ALGS.add(Curve25519Exchange.NAME);
		KEX_ALGS.add(Curve25519Exchange.ALT_NAME);
		if (supportsEc) {
			KEX_ALGS.add("ecdh-sha2-nistp256");
			KEX_ALGS.add("ecdh-sha2-nistp384");
			KEX_ALGS.add("ecdh-sha2-nistp521");
		}
		KEX_ALGS.add("diffie-hellman-group18-sha512");
		KEX_ALGS.add("diffie-hellman-group16-sha512");
		KEX_ALGS.add("diffie-hellman-group-exchange-sha256");
		KEX_ALGS.add("diffie-hellman-group14-sha256");
		KEX_ALGS.add("diffie-hellman-group-exchange-sha1");
		KEX_ALGS.add("diffie-hellman-group14-sha1");
		KEX_ALGS.add("diffie-hellman-group1-sha1");

		// Indicate client support for ext-info
		KEX_ALGS.add("ext-info-c");
	}

	private KexState kxs;
	private int kexCount = 0;
	private KeyMaterial km;
	byte[] sessionId;
	private ClientServerHello csh;

	private final Object accessLock = new Object();
	private ConnectionInfo lastConnInfo = null;

	private boolean connectionClosed = false;

	private boolean ignore_next_kex_packet = false;

	private final TransportManager tm;

	private CryptoWishList nextKEXcryptoWishList;
	private DHGexParameters nextKEXdhgexParameters;

	private ServerHostKeyVerifier verifier;
	private final String hostname;
	private final int port;
	private final SecureRandom rnd;

	public KexManager(TransportManager tm, ClientServerHello csh, CryptoWishList initialCwl, String hostname, int port,
			ServerHostKeyVerifier keyVerifier, SecureRandom rnd)
	{
		this.tm = tm;
		this.csh = csh;
		this.nextKEXcryptoWishList = initialCwl;
		this.nextKEXdhgexParameters = new DHGexParameters();
		this.hostname = hostname;
		this.port = port;
		this.verifier = keyVerifier;
		this.rnd = rnd;
	}

	public ConnectionInfo getOrWaitForConnectionInfo(int minKexCount) throws IOException
	{
		synchronized (accessLock)
		{
			while (true)
			{
				if ((lastConnInfo != null) && (lastConnInfo.keyExchangeCounter >= minKexCount))
					return lastConnInfo;

				if (connectionClosed)
					throw new IOException("Key exchange was not finished, connection is closed.", tm.getReasonClosedCause());

				try
				{
					accessLock.wait();
				}
				catch (InterruptedException ignore)
				{
				}
			}
		}
	}

	private String getFirstMatch(String[] client, String[] server) throws NegotiateException
	{
		if (client == null || server == null)
			throw new IllegalArgumentException();

		if (client.length == 0)
			return null;

		for (String aClient : client) {
			for (String aServer : server) {
				if (aClient.equals(aServer))
					return aClient;
			}
		}
		throw new NegotiateException();
	}

	private boolean compareFirstOfNameList(String[] a, String[] b)
	{
		if (a == null || b == null)
			throw new IllegalArgumentException();

		if ((a.length == 0) && (b.length == 0))
			return true;

		if ((a.length == 0) || (b.length == 0))
			return false;

		return (a[0].equals(b[0]));
	}

	private boolean isGuessOK(KexParameters cpar, KexParameters spar)
	{
		if (cpar == null || spar == null)
			throw new IllegalArgumentException();

		if (!compareFirstOfNameList(cpar.kex_algorithms, spar.kex_algorithms))
		{
			return false;
		}

		return compareFirstOfNameList(cpar.server_host_key_algorithms, spar.server_host_key_algorithms);
	}

	private NegotiatedParameters mergeKexParameters(KexParameters client, KexParameters server)
	{
		NegotiatedParameters np = new NegotiatedParameters();

		try
		{
			np.kex_algo = getFirstMatch(client.kex_algorithms, server.kex_algorithms);

			log.log(20, "kex_algo=" + np.kex_algo);

			np.server_host_key_algo = getFirstMatch(client.server_host_key_algorithms,
					server.server_host_key_algorithms);

			log.log(20, "server_host_key_algo=" + np.server_host_key_algo);

			np.enc_algo_client_to_server = getFirstMatch(client.encryption_algorithms_client_to_server,
					server.encryption_algorithms_client_to_server);
			np.enc_algo_server_to_client = getFirstMatch(client.encryption_algorithms_server_to_client,
					server.encryption_algorithms_server_to_client);

			log.log(20, "enc_algo_client_to_server=" + np.enc_algo_client_to_server);
			log.log(20, "enc_algo_server_to_client=" + np.enc_algo_server_to_client);

			np.mac_algo_client_to_server = getFirstMatch(client.mac_algorithms_client_to_server,
					server.mac_algorithms_client_to_server);
			np.mac_algo_server_to_client = getFirstMatch(client.mac_algorithms_server_to_client,
					server.mac_algorithms_server_to_client);

			log.log(20, "mac_algo_client_to_server=" + np.mac_algo_client_to_server);
			log.log(20, "mac_algo_server_to_client=" + np.mac_algo_server_to_client);

			np.comp_algo_client_to_server = getFirstMatch(client.compression_algorithms_client_to_server,
					server.compression_algorithms_client_to_server);
			np.comp_algo_server_to_client = getFirstMatch(client.compression_algorithms_server_to_client,
					server.compression_algorithms_server_to_client);

			log.log(20, "comp_algo_client_to_server=" + np.comp_algo_client_to_server);
			log.log(20, "comp_algo_server_to_client=" + np.comp_algo_server_to_client);

		}
		catch (NegotiateException e)
		{
			return null;
		}

		try
		{
			np.lang_client_to_server = getFirstMatch(client.languages_client_to_server,
					server.languages_client_to_server);
		}
		catch (NegotiateException e1)
		{
			np.lang_client_to_server = null;
		}

		try
		{
			np.lang_server_to_client = getFirstMatch(client.languages_server_to_client,
					server.languages_server_to_client);
		}
		catch (NegotiateException e2)
		{
			np.lang_server_to_client = null;
		}

		if (isGuessOK(client, server))
			np.guessOK = true;

		return np;
	}

	public synchronized void initiateKEX(CryptoWishList cwl, DHGexParameters dhgex) throws IOException
	{
		nextKEXcryptoWishList = cwl;
		filterHostKeyTypes(nextKEXcryptoWishList);

		nextKEXdhgexParameters = dhgex;

		if (kxs == null)
		{
			kxs = new KexState();

			kxs.dhgexParameters = nextKEXdhgexParameters;
			PacketKexInit kp = new PacketKexInit(nextKEXcryptoWishList);
			kxs.localKEX = kp;
			tm.sendKexMessage(kp.getPayload());
		}
	}

	/**
	 * If the verifier can indicate which algorithms it knows about for this host, then
	 * filter out our crypto wish list to only include those algorithms. Otherwise we'll
	 * negotiate a host key we have not previously confirmed.
	 *
	 * @param cwl crypto wish list to filter
	 */
	private void filterHostKeyTypes(CryptoWishList cwl) {
		if (verifier instanceof ExtendedServerHostKeyVerifier) {
			ExtendedServerHostKeyVerifier extendedVerifier = (ExtendedServerHostKeyVerifier) verifier;

			List<String> knownAlgorithms = extendedVerifier.getKnownKeyAlgorithmsForHost(hostname, port);
			if (knownAlgorithms != null && knownAlgorithms.size() > 0) {
				ArrayList<String> filteredAlgorithms = new ArrayList<>(knownAlgorithms.size());

				/*
				 * Look at our current wish list and adjust it based on what the client already knows, but
				 * be careful to keep it in the order desired by the wish list.
				 */
				for (String capableAlgo : cwl.serverHostKeyAlgorithms) {
					for (String knownAlgo : knownAlgorithms) {
						if (capableAlgo.equals(knownAlgo)) {
							filteredAlgorithms.add(knownAlgo);
						}
					}
				}

				if (filteredAlgorithms.size() > 0) {
					cwl.serverHostKeyAlgorithms = filteredAlgorithms.toArray(new String[0]);
				}
			}
		}
	}

	private void establishKeyMaterial() throws IOException
	{
		try
		{
			int mac_cs_key_len = MACs.getKeyLen(kxs.np.mac_algo_client_to_server);
			int enc_cs_key_len = BlockCipherFactory.getKeySize(kxs.np.enc_algo_client_to_server);
			int enc_cs_block_len = BlockCipherFactory.getBlockSize(kxs.np.enc_algo_client_to_server);

			int mac_sc_key_len = MACs.getKeyLen(kxs.np.mac_algo_server_to_client);
			int enc_sc_key_len = BlockCipherFactory.getKeySize(kxs.np.enc_algo_server_to_client);
			int enc_sc_block_len = BlockCipherFactory.getBlockSize(kxs.np.enc_algo_server_to_client);

			km = KeyMaterial.create(kxs.hashAlgo, kxs.H, kxs.K, sessionId, enc_cs_key_len, enc_cs_block_len, mac_cs_key_len,
					enc_sc_key_len, enc_sc_block_len, mac_sc_key_len);
		}
		catch (IllegalArgumentException e)
		{
			throw new IOException("Could not establish key material: " + e.getMessage());
		}
	}

	private void finishKex() throws IOException
	{
		if (sessionId == null)
			sessionId = kxs.H;

		establishKeyMaterial();

		/* Tell the other side that we start using the new material */

		PacketNewKeys ign = new PacketNewKeys();
		tm.sendKexMessage(ign.getPayload());

		BlockCipher cbc;
		MAC mac;
		ICompressor comp;

		try
		{
			cbc = BlockCipherFactory.createCipher(kxs.np.enc_algo_client_to_server, true, km.enc_key_client_to_server,
					km.initial_iv_client_to_server);

			mac = new HMAC(kxs.np.mac_algo_client_to_server, km.integrity_key_client_to_server);
			
			comp = CompressionFactory.createCompressor(kxs.np.comp_algo_client_to_server);

		}
		catch (IllegalArgumentException e1)
		{
			throw new IOException("Fatal error during MAC startup!");
		}

		tm.changeSendCipher(cbc, mac);
		tm.changeSendCompression(comp);
		tm.kexFinished();
	}

	public static String[] getDefaultServerHostkeyAlgorithmList()
	{
		return HOSTKEY_ALGS.toArray(new String[0]);
	}

	public static void checkServerHostkeyAlgorithmsList(String[] algos)
	{
		for (String algo : algos) {
			if (!HOSTKEY_ALGS.contains(algo))
				throw new IllegalArgumentException("Unknown server host key algorithm '" + algo + "'");
		}
	}

	public static String[] getDefaultKexAlgorithmList()
	{
		return KEX_ALGS.toArray(new String[0]);
	}

	public static void checkKexAlgorithmList(String[] algos)
	{
		for (String algo : algos) {
			if (!KEX_ALGS.contains(algo))
				throw new IllegalArgumentException("Unknown kex algorithm '" + algo + "'");
		}
	}

	private boolean verifySignature(byte[] sig, byte[] hostkey) throws IOException
	{
		if (kxs.np.server_host_key_algo.equals(Ed25519Verify.ED25519_ID)) {
			byte[] eds = Ed25519Verify.decodeSSHEd25519Signature(sig);
			EdDSAPublicKey edpk = Ed25519Verify.decodeSSHEd25519PublicKey(hostkey);

			log.log(50, "Verifying ed25519 signature");

			return Ed25519Verify.verifySignature(kxs.H, eds, edpk);

		}
		if (kxs.np.server_host_key_algo.startsWith("ecdsa-sha2-"))
		{
			byte[] rs = ECDSASHA2Verify.decodeSSHECDSASignature(sig);
			ECPublicKey epk = ECDSASHA2Verify.decodeSSHECDSAPublicKey(hostkey);

			log.log(50, "Verifying ecdsa signature");

			return ECDSASHA2Verify.verifySignature(kxs.H, rs, epk);
		}

		if (kxs.np.server_host_key_algo.equals("ssh-rsa"))
		{
			byte[] rs = RSASHA1Verify.decodeSSHRSASignature(sig);
			RSAPublicKey rpk = RSASHA1Verify.decodeSSHRSAPublicKey(hostkey);

			log.log(50, "Verifying ssh-rsa signature");

			return RSASHA1Verify.verifySignature(kxs.H, rs, rpk);
		}

		if (kxs.np.server_host_key_algo.equals("rsa-sha2-256"))
		{
			byte[] rs = RSASHA256Verify.decodeRSASHA256Signature(sig);
			RSAPublicKey rpk = RSASHA1Verify.decodeSSHRSAPublicKey(hostkey);

			log.log(50, "Verifying rsa-sha2-256 signature");

			return RSASHA256Verify.verifySignature(kxs.H, rs, rpk);
		}

		if (kxs.np.server_host_key_algo.equals("rsa-sha2-512"))
		{
			byte[] rs = RSASHA512Verify.decodeRSASHA512Signature(sig);
			RSAPublicKey rpk = RSASHA1Verify.decodeSSHRSAPublicKey(hostkey);

			log.log(50, "Verifying rsa-sha2-512 signature");

			return RSASHA512Verify.verifySignature(kxs.H, rs, rpk);
		}

		if (kxs.np.server_host_key_algo.equals("ssh-dss"))
		{
			byte[] ds = DSASHA1Verify.decodeSSHDSASignature(sig);
			DSAPublicKey dpk = DSASHA1Verify.decodeSSHDSAPublicKey(hostkey);

			log.log(50, "Verifying ssh-dss signature");

			return DSASHA1Verify.verifySignature(kxs.H, ds, dpk);
		}

		throw new IOException("Unknown server host key algorithm '" + kxs.np.server_host_key_algo + "'");
	}

	public synchronized void handleMessage(byte[] msg, int msglen) throws IOException
	{
		PacketKexInit kip;

		if (msg == null)
		{
			synchronized (accessLock)
			{
				connectionClosed = true;
				accessLock.notifyAll();
				return;
			}
		}

		if ((kxs == null) && (msg[0] != Packets.SSH_MSG_KEXINIT))
			throw new IOException("Unexpected KEX message (type " + msg[0] + ")");

		if (ignore_next_kex_packet)
		{
			ignore_next_kex_packet = false;
			return;
		}

		if (msg[0] == Packets.SSH_MSG_KEXINIT)
		{
			if ((kxs != null) && (kxs.state != 0))
				throw new IOException("Unexpected SSH_MSG_KEXINIT message during on-going kex exchange!");

			if (kxs == null)
			{
				/*
				 * Ah, OK, peer wants to do KEX. Let's be nice and play
				 * together.
				 */
				kxs = new KexState();
				kxs.dhgexParameters = nextKEXdhgexParameters;
				kip = new PacketKexInit(nextKEXcryptoWishList);
				kxs.localKEX = kip;
				tm.sendKexMessage(kip.getPayload());
			}

			kip = new PacketKexInit(msg, 0, msglen);
			kxs.remoteKEX = kip;

			kxs.np = mergeKexParameters(kxs.localKEX.getKexParameters(), kxs.remoteKEX.getKexParameters());

			if (kxs.np == null)
				throw new IOException("Cannot negotiate, proposals do not match.");

			if (kxs.remoteKEX.isFirst_kex_packet_follows() && (!kxs.np.guessOK))
			{
				/*
				 * Guess was wrong, we need to ignore the next kex packet.
				 */

				ignore_next_kex_packet = true;
			}

			if (kxs.np.kex_algo.equals("diffie-hellman-group-exchange-sha1")
					|| kxs.np.kex_algo.equals("diffie-hellman-group-exchange-sha256"))
			{
				if (kxs.dhgexParameters.getMin_group_len() == 0 || csh.server_versioncomment.matches("OpenSSH_2\\.([0-4]\\.|5\\.[0-2]).*"))
				{
					PacketKexDhGexRequestOld dhgexreq = new PacketKexDhGexRequestOld(kxs.dhgexParameters);
					tm.sendKexMessage(dhgexreq.getPayload());
				}
				else
				{
					PacketKexDhGexRequest dhgexreq = new PacketKexDhGexRequest(kxs.dhgexParameters);
					tm.sendKexMessage(dhgexreq.getPayload());
				}
				if (kxs.np.kex_algo.endsWith("sha1")) {
					kxs.hashAlgo = "SHA1";
				} else {
					kxs.hashAlgo = "SHA-256";
				}
				kxs.state = 1;
				return;
			}

			if (kxs.np.kex_algo.equals(Curve25519Exchange.NAME)
					|| kxs.np.kex_algo.equals(Curve25519Exchange.ALT_NAME)
					|| kxs.np.kex_algo.equals("ecdh-sha2-nistp521")
					|| kxs.np.kex_algo.equals("ecdh-sha2-nistp384")
					|| kxs.np.kex_algo.equals("ecdh-sha2-nistp256")
					|| kxs.np.kex_algo.equals("diffie-hellman-group18-sha512")
					|| kxs.np.kex_algo.equals("diffie-hellman-group16-sha512")
					|| kxs.np.kex_algo.equals("diffie-hellman-group14-sha256")
					|| kxs.np.kex_algo.equals("diffie-hellman-group14-sha1")
					|| kxs.np.kex_algo.equals("diffie-hellman-group1-sha1")) {
				kxs.dhx = GenericDhExchange.getInstance(kxs.np.kex_algo);

				kxs.dhx.init(kxs.np.kex_algo);
				kxs.hashAlgo = kxs.dhx.getHashAlgo();

				PacketKexDHInit kp = new PacketKexDHInit(kxs.dhx.getE());
				tm.sendKexMessage(kp.getPayload());
				kxs.state = 1;
				return;
			}

			throw new IllegalStateException("Unknown KEX method!");
		}

		if (msg[0] == Packets.SSH_MSG_NEWKEYS)
		{
			if (km == null)
				throw new IOException("Peer sent SSH_MSG_NEWKEYS, but I have no key material ready!");

			BlockCipher cbc;
			MAC mac;
			ICompressor comp;

			try
			{
				cbc = BlockCipherFactory.createCipher(kxs.np.enc_algo_server_to_client, false,
						km.enc_key_server_to_client, km.initial_iv_server_to_client);

				mac = new HMAC(kxs.np.mac_algo_server_to_client, km.integrity_key_server_to_client);
				
				comp = CompressionFactory.createCompressor(kxs.np.comp_algo_server_to_client);
			}
			catch (IllegalArgumentException e1)
			{
				throw new IOException("Fatal error during MAC startup: " + e1.getMessage());
			}

			tm.changeRecvCipher(cbc, mac);
			tm.changeRecvCompression(comp);

			ConnectionInfo sci = new ConnectionInfo();

			kexCount++;

			sci.keyExchangeAlgorithm = kxs.np.kex_algo;
			sci.keyExchangeCounter = kexCount;
			sci.clientToServerCryptoAlgorithm = kxs.np.enc_algo_client_to_server;
			sci.serverToClientCryptoAlgorithm = kxs.np.enc_algo_server_to_client;
			sci.clientToServerMACAlgorithm = kxs.np.mac_algo_client_to_server;
			sci.serverToClientMACAlgorithm = kxs.np.mac_algo_server_to_client;
			sci.serverHostKeyAlgorithm = kxs.np.server_host_key_algo;
			sci.serverHostKey = kxs.hostkey;
			sci.clientToServerCompressionAlgorithm = kxs.np.comp_algo_client_to_server;
			sci.serverToClientCompressionAlgorithm = kxs.np.comp_algo_server_to_client;

			synchronized (accessLock)
			{
				lastConnInfo = sci;
				accessLock.notifyAll();
			}

			kxs = null;
			return;
		}

		if ((kxs == null) || (kxs.state == 0))
			throw new IOException("Unexpected Kex submessage!");

		if (kxs.np.kex_algo.equals("diffie-hellman-group-exchange-sha1")
				|| kxs.np.kex_algo.equals("diffie-hellman-group-exchange-sha256"))
		{
			if (kxs.state == 1)
			{
				PacketKexDhGexGroup dhgexgrp = new PacketKexDhGexGroup(msg, 0, msglen);
				kxs.dhgx = new DhGroupExchange(dhgexgrp.getP(), dhgexgrp.getG());
				kxs.dhgx.init(rnd);
				PacketKexDhGexInit dhgexinit = new PacketKexDhGexInit(kxs.dhgx.getE());
				tm.sendKexMessage(dhgexinit.getPayload());
				kxs.state = 2;
				return;
			}

			if (kxs.state == 2)
			{
				PacketKexDhGexReply dhgexrpl = new PacketKexDhGexReply(msg, 0, msglen);

				kxs.hostkey = dhgexrpl.getHostKey();

				if (verifier != null)
				{
					boolean vres = false;

					try
					{
						vres = verifier.verifyServerHostKey(hostname, port, kxs.np.server_host_key_algo, kxs.hostkey);
					}
					catch (Exception e)
					{
						throw new IOException(
								"The server hostkey was not accepted by the verifier callback.", e);
					}

					if (!vres)
						throw new IOException("The server hostkey was not accepted by the verifier callback");
				}

				kxs.dhgx.setF(dhgexrpl.getF());

				try
				{
					kxs.H = kxs.dhgx.calculateH(kxs.hashAlgo,
							csh.getClientString(), csh.getServerString(),
							kxs.localKEX.getPayload(), kxs.remoteKEX.getPayload(),
							dhgexrpl.getHostKey(), kxs.dhgexParameters);
				}
				catch (IllegalArgumentException e)
				{
					throw new IOException("KEX error.", e);
				}

				boolean res = verifySignature(dhgexrpl.getSignature(), kxs.hostkey);

				if (!res)
					throw new IOException("Hostkey signature sent by remote is wrong!");

				kxs.K = kxs.dhgx.getK();

				finishKex();
				kxs.state = -1;
				return;
			}

			throw new IllegalStateException("Illegal State in KEX Exchange!");
		}

		if (kxs.np.kex_algo.equals("diffie-hellman-group1-sha1")
				|| kxs.np.kex_algo.equals("diffie-hellman-group14-sha1")
				|| kxs.np.kex_algo.equals("diffie-hellman-group14-sha256")
				|| kxs.np.kex_algo.equals("diffie-hellman-group16-sha512")
				|| kxs.np.kex_algo.equals("diffie-hellman-group18-sha512")
				|| kxs.np.kex_algo.equals("ecdh-sha2-nistp256")
				|| kxs.np.kex_algo.equals("ecdh-sha2-nistp384")
				|| kxs.np.kex_algo.equals("ecdh-sha2-nistp521")
				|| kxs.np.kex_algo.equals(Curve25519Exchange.NAME)
				|| kxs.np.kex_algo.equals(Curve25519Exchange.ALT_NAME))
		{
			if (kxs.state == 1)
			{

				PacketKexDHReply dhr = new PacketKexDHReply(msg, 0, msglen);

				kxs.hostkey = dhr.getHostKey();

				if (verifier != null)
				{
					boolean vres = false;

					try
					{
						vres = verifier.verifyServerHostKey(hostname, port, kxs.np.server_host_key_algo, kxs.hostkey);
					}
					catch (Exception e)
					{
						throw new IOException(
								"The server hostkey was not accepted by the verifier callback.", e);
					}

					if (!vres)
						throw new IOException("The server hostkey was not accepted by the verifier callback");
				}

				kxs.dhx.setF(dhr.getF());

				try
				{
					kxs.H = kxs.dhx.calculateH(csh.getClientString(), csh.getServerString(), kxs.localKEX.getPayload(),
							kxs.remoteKEX.getPayload(), dhr.getHostKey());
				}
				catch (IllegalArgumentException e)
				{
					throw new IOException("KEX error.", e);
				}

				boolean res = verifySignature(dhr.getSignature(), kxs.hostkey);

				if (!res)
					throw new IOException("Hostkey signature sent by remote is wrong!");

				kxs.K = kxs.dhx.getK();

				finishKex();
				kxs.state = -1;
				return;
			}
		}

		throw new IllegalStateException("Unkown KEX method! (" + kxs.np.kex_algo + ")");
	}
}

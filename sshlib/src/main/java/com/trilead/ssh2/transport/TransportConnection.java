
package com.trilead.ssh2.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import com.trilead.ssh2.compression.ICompressor;
import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.cipher.CipherInputStream;
import com.trilead.ssh2.crypto.cipher.CipherOutputStream;
import com.trilead.ssh2.crypto.cipher.NullCipher;
import com.trilead.ssh2.crypto.digest.MAC;
import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.Packets;


/**
 * TransportConnection.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: TransportConnection.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */
public class TransportConnection
{
	private static final Logger log = Logger.getLogger(TransportConnection.class);

	int send_seq_number = 0;

	int recv_seq_number = 0;

	CipherInputStream cis;

	CipherOutputStream cos;

	boolean useRandomPadding = false;

	/* Depends on current MAC and CIPHER */

	MAC send_mac;

	byte[] send_mac_buffer;

	int send_padd_blocksize = 8;

	MAC recv_mac;

	byte[] recv_mac_buffer;

	byte[] recv_mac_buffer_cmp;

	int recv_padd_blocksize = 8;
	
	ICompressor recv_comp = null;
	
	ICompressor send_comp = null;
	
	boolean can_recv_compress = false;

	boolean can_send_compress = false;

	byte[] recv_comp_buffer;
	
	byte[] send_comp_buffer;

	/* won't change */

	final byte[] send_padding_buffer = new byte[256];

	final byte[] send_packet_header_buffer = new byte[5];

	final byte[] recv_padding_buffer = new byte[256];

	final byte[] recv_packet_header_buffer = new byte[5];

	ClientServerHello csh;

	final SecureRandom rnd;

	public TransportConnection(InputStream is, OutputStream os, SecureRandom rnd)
	{
		this.cis = new CipherInputStream(new NullCipher(), is);
		this.cos = new CipherOutputStream(new NullCipher(), os);
		this.rnd = rnd;
	}

	public void changeRecvCipher(BlockCipher bc, MAC mac)
	{
		cis.changeCipher(bc);
		recv_mac = mac;
		recv_mac_buffer = (mac != null) ? new byte[mac.size()] : null;
		recv_mac_buffer_cmp = (mac != null) ? new byte[mac.size()] : null;
		recv_padd_blocksize = bc.getBlockSize();
		if (recv_padd_blocksize < 8)
			recv_padd_blocksize = 8;
	}

	public void changeSendCipher(BlockCipher bc, MAC mac)
	{
		if (!(bc instanceof NullCipher))
		{
			/* Only use zero byte padding for the first few packets */
			useRandomPadding = true;
			/* Once we start encrypting, there is no way back */
		}

		cos.changeCipher(bc);
		send_mac = mac;
		send_mac_buffer = (mac != null) ? new byte[mac.size()] : null;
		send_padd_blocksize = bc.getBlockSize();
		if (send_padd_blocksize < 8)
			send_padd_blocksize = 8;
	}
	
	public void changeRecvCompression(ICompressor comp)
	{
		recv_comp = comp;
		
		if (comp != null) {
			recv_comp_buffer = new byte[comp.getBufferSize()];
			can_recv_compress |= recv_comp.canCompressPreauth();
		}
	}

	public void changeSendCompression(ICompressor comp)
	{
		send_comp = comp;
		
		if (comp != null) {
			send_comp_buffer = new byte[comp.getBufferSize()];
			can_send_compress |= send_comp.canCompressPreauth();
		}
	}
	
	public void sendMessage(byte[] message) throws IOException
	{
		sendMessage(message, 0, message.length, 0);
	}

	public void sendMessage(byte[] message, int off, int len) throws IOException
	{
		sendMessage(message, off, len, 0);
	}

	public int getPacketOverheadEstimate()
	{
		// return an estimate for the paket overhead (for send operations)
		return 5 + 4 + (send_padd_blocksize - 1) + send_mac_buffer.length;
	}

	public void sendMessage(byte[] message, int off, int len, int padd) throws IOException
	{
		if (padd < 4)
			padd = 4;
		else if (padd > 64)
			padd = 64;
		
		if (send_comp != null && can_send_compress) {
			if (send_comp_buffer.length < message.length + 1024)
				send_comp_buffer = new byte[message.length + 1024];
			len = send_comp.compress(message, off, len, send_comp_buffer);
			message = send_comp_buffer;
		}

		boolean encryptThenMac = send_mac != null && send_mac.isEncryptThenMac();

		int encryptedPacketLength = (encryptThenMac ? 1 : 5) + len + padd; /* Minimum allowed padding is 4 */

		int slack = encryptedPacketLength % send_padd_blocksize;

		if (slack != 0)
		{
			encryptedPacketLength += (send_padd_blocksize - slack);
		}

		if (encryptedPacketLength < 16)
			encryptedPacketLength = 16;

		int padd_len = encryptedPacketLength - ((encryptThenMac ? 1 : 5) + len);

		if (useRandomPadding)
		{
			for (int i = 0; i < padd_len; i = i + 4)
			{
				/*
				 * don't waste calls to rnd.nextInt() (by using only 8bit of the
				 * output). just believe me: even though we may write here up to 3
				 * bytes which won't be used, there is no "buffer overflow" (i.e.,
				 * arrayindexoutofbounds). the padding buffer is big enough =) (256
				 * bytes, and that is bigger than any current cipher block size + 64).
				 */

				int r = rnd.nextInt();
				send_padding_buffer[i] = (byte) r;
				send_padding_buffer[i + 1] = (byte) (r >> 8);
				send_padding_buffer[i + 2] = (byte) (r >> 16);
				send_padding_buffer[i + 3] = (byte) (r >> 24);
			}
		}
		else
		{
			/* use zero padding for unencrypted traffic */
			for (int i = 0; i < padd_len; i++)
				send_padding_buffer[i] = 0;
			/* Actually this code is paranoid: we never filled any
			 * bytes into the padding buffer so far, therefore it should
			 * consist of zeros only.
			 */
		}

		int payloadLength = encryptThenMac ? encryptedPacketLength : encryptedPacketLength - 4;
		send_packet_header_buffer[0] = (byte) (encryptedPacketLength >> 24);
		send_packet_header_buffer[1] = (byte) (payloadLength >> 16);
		send_packet_header_buffer[2] = (byte) (payloadLength >> 8);
		send_packet_header_buffer[3] = (byte) (payloadLength);
		send_packet_header_buffer[4] = (byte) padd_len;

		if (send_mac != null && send_mac.isEncryptThenMac()) {
			cos.writePlain(send_packet_header_buffer, 0, 4);
			cos.startRecording();
			cos.write(send_packet_header_buffer, 4, 1);
		} else {
			cos.write(send_packet_header_buffer, 0, 5);
		}
		cos.write(message, off, len);
		cos.write(send_padding_buffer, 0, padd_len);

		if (send_mac != null)
		{
			send_mac.initMac(send_seq_number);

			if (send_mac.isEncryptThenMac()) {
				send_mac.update(send_packet_header_buffer, 0, 4);
				byte[] encryptedMessage = cos.getRecordedOutput();
				send_mac.update(encryptedMessage, 0, encryptedMessage.length);
			} else {
				send_mac.update(send_packet_header_buffer, 0, 5);
				send_mac.update(message, off, len);
				send_mac.update(send_padding_buffer, 0, padd_len);
			}

			send_mac.getMac(send_mac_buffer, 0);
			cos.writePlain(send_mac_buffer, 0, send_mac_buffer.length);
		}

		cos.flush();

		if (log.isEnabled())
		{
			log.log(90, "Sent " + Packets.getMessageName(message[off] & 0xff) + " " + len + " bytes payload");
		}

		send_seq_number++;
	}

	public int receiveMessage(byte buffer[], int off, int len) throws IOException
	{
		final int packetLength;
		final int payloadLength;

		if (recv_mac != null && recv_mac.isEncryptThenMac()) {
			cis.readPlain(recv_packet_header_buffer, 0, 4);
			packetLength = getPacketLength(recv_packet_header_buffer, true);

			recv_mac.initMac(recv_seq_number);
			recv_mac.update(recv_packet_header_buffer, 0, 4);

			cis.peekPlain(buffer, off, packetLength + recv_mac_buffer.length);
			System.arraycopy(buffer, off + packetLength, recv_mac_buffer, 0, recv_mac_buffer.length);

			recv_mac.update(buffer, off, packetLength);
			recv_mac.getMac(recv_mac_buffer_cmp, 0);

			checkMacMatches(recv_mac_buffer, recv_mac_buffer_cmp);

			cis.read(recv_packet_header_buffer, 4, 1);
		} else {
			cis.read(recv_packet_header_buffer, 0, 5);
			packetLength = getPacketLength(recv_packet_header_buffer, false);
		}

		int paddingLength = recv_packet_header_buffer[4] & 0xff;

		payloadLength = calculatePayloadLength(len, packetLength, paddingLength);

		cis.read(buffer, off, payloadLength);
		cis.read(recv_padding_buffer, 0, paddingLength);

		if (recv_mac != null) {
			cis.readPlain(recv_mac_buffer, 0, recv_mac_buffer.length);

			if (!recv_mac.isEncryptThenMac()) {
				recv_mac.initMac(recv_seq_number);
				recv_mac.update(recv_packet_header_buffer, 0, 5);
				recv_mac.update(buffer, off, payloadLength);
				recv_mac.update(recv_padding_buffer, 0, paddingLength);
				recv_mac.getMac(recv_mac_buffer_cmp, 0);

				checkMacMatches(recv_mac_buffer, recv_mac_buffer_cmp);
			}
		}

		recv_seq_number++;

		if (log.isEnabled()) {
			log.log(90, "Received " + Packets.getMessageName(buffer[off] & 0xff) + " " + payloadLength
					+ " bytes payload");
		}

		if (recv_comp != null && can_recv_compress) {
			int[] uncomp_len = new int[] { payloadLength };
			buffer = recv_comp.uncompress(buffer, off, uncomp_len);
			
			if (buffer == null) {
				throw new IOException("Error while inflating remote data");
			} else {
				return uncomp_len[0];
			}
		} else {
			return payloadLength;
		}
	}

	private static int calculatePayloadLength(int bufferLength, int packetLength, int paddingLength) throws IOException {
		int payloadLength = packetLength - paddingLength - 1;

		if (payloadLength < 0)
			throw new IOException("Illegal padding_length in packet from remote (" + paddingLength + ")");

		if (payloadLength >= bufferLength)
			throw new IOException("Receive buffer too small (" + bufferLength + ", need " + payloadLength + ")");

		return payloadLength;
	}

	private static void checkMacMatches(byte[] buf1, byte[] buf2) throws IOException {
		int difference = 0;
		for (int i = 0; i < buf1.length; i++) {
			difference |= buf1[i] ^ buf2[i];
		}
		if (difference != 0)
			throw new IOException("Remote sent corrupt MAC.");
	}

	private static int getPacketLength(byte[] packetHeader, boolean isEtm) throws IOException {
		int packetLength = ((packetHeader[0] & 0xff) << 24)
						| ((packetHeader[1] & 0xff) << 16) | ((packetHeader[2] & 0xff) << 8)
						| ((packetHeader[3] & 0xff));

		if (packetLength > 35000 || packetLength < (isEtm ? 8 : 12))
			throw new IOException("Illegal packet size! (" + packetLength + ")");

		return packetLength;
	}

	/**
	 * 
	 */
	public void startCompression() {
		can_recv_compress = true;
		can_send_compress = true;
	}
}


package com.trilead.ssh2.crypto.cipher;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * CipherOutputStream.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: CipherOutputStream.java,v 1.1 2007/10/15 12:49:55 cplattne Exp $
 */
public class CipherOutputStream
{
	private BlockCipher currentCipher;
	private final BufferedOutputStream bo;
	private byte[] buffer;
	private byte[] enc;
	private int blockSize;
	private int pos;
	private boolean recordingOutput;
	private final ByteArrayOutputStream recordingOutputStream = new ByteArrayOutputStream();

	public CipherOutputStream(BlockCipher tc, OutputStream bo)
	{
		if (bo instanceof BufferedOutputStream) {
			this.bo = (BufferedOutputStream) bo;
		} else {
			this.bo = new BufferedOutputStream(bo);
		}
		changeCipher(tc);
	}

	public void flush() throws IOException
	{
		if (pos != 0)
			throw new IOException("FATAL: cannot flush since crypto buffer is not aligned.");

		bo.flush();
	}

	public void changeCipher(BlockCipher bc)
	{
		this.currentCipher = bc;
		blockSize = bc.getBlockSize();
		buffer = new byte[blockSize];
		enc = new byte[blockSize];
		pos = 0;
	}

	public void startRecording() {
		recordingOutput = true;
	}

	public byte[] getRecordedOutput() {
		recordingOutput = false;
		byte[] recordedOutput = recordingOutputStream.toByteArray();
		recordingOutputStream.reset();
		return recordedOutput;
	}

	private void writeBlock() throws IOException
	{
		try
		{
			currentCipher.transformBlock(buffer, 0, enc, 0);
		}
		catch (Exception e)
		{
			throw new IOException("Error while decrypting block.", e);
		}

		bo.write(enc, 0, blockSize);
		pos = 0;

		if (recordingOutput) {
			recordingOutputStream.write(enc, 0, blockSize);
		}
	}

	public void write(byte[] src, int off, int len) throws IOException
	{
		while (len > 0)
		{
			int avail = blockSize - pos;
			int copy = Math.min(avail, len);

			System.arraycopy(src, off, buffer, pos, copy);
			pos += copy;
			off += copy;
			len -= copy;

			if (pos >= blockSize)
				writeBlock();
		}
	}

	public void write(int b) throws IOException
	{
		buffer[pos++] = (byte) b;
		if (pos >= blockSize)
			writeBlock();
	}

	public void writePlain(int b) throws IOException
	{
		if (pos != 0)
			throw new IOException("Cannot write plain since crypto buffer is not aligned.");
		bo.write(b);
	}

	public void writePlain(byte[] b, int off, int len) throws IOException
	{
		if (pos != 0)
			throw new IOException("Cannot write plain since crypto buffer is not aligned.");
		bo.write(b, off, len);
	}
}

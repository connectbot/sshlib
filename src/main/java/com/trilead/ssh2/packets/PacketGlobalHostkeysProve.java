/*
 * ConnectBot: simple, powerful, open-source SSH client for Android
 * Copyright 2016 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.trilead.ssh2.packets;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * PacketGlobalHostkeysProve implements the hostkeys-prove-00@openssh.com packet specified in
 * <a href="https://github.com/openssh/openssh-portable/blob/deb8d99ecba70b67f4af7880b11ca8768df9ec3a/PROTOCOL">OpenSSH documentation</a>.
 *
 * @author Kenny Root
 */
public class PacketGlobalHostkeysProve
{
	public static final String HOSTKEYS_PROVE_STANDARD = "hostkeys-prove";
	public static final String HOSTKEYS_PROVE_VENDOR = "hostkeys-prove-00@openssh.com";

	private final byte[] payload;
	private final ArrayList<byte[]> hostKeys;
	private final ArrayList<byte[]> signatures;
	private final String requestName;

	public PacketGlobalHostkeysProve(String requestName, List<byte[]> hostKeys)
	{
		this.requestName = requestName;
		this.hostKeys = new ArrayList<>(hostKeys);
		this.payload = null;
		this.signatures = null;
	}

	public PacketGlobalHostkeysProve(byte[] data, int off, int len, boolean isResponse) throws IOException
	{
		this.payload = new byte[len];
		System.arraycopy(data, off, this.payload, 0, len);

		TypesReader tr = new TypesReader(data, off, len);

		int packet_type = tr.readByte();

		if (isResponse) {
			if (packet_type != Packets.SSH_MSG_REQUEST_SUCCESS)
				throw new IOException("This is not a SSH_MSG_REQUEST_SUCCESS! (" + packet_type + ")");

			this.signatures = new ArrayList<byte[]>();
			while (tr.remain() != 0) {
				signatures.add(tr.readByteString());
			}

			this.hostKeys = null;
			this.requestName = null;
		} else {
			if (packet_type != Packets.SSH_MSG_GLOBAL_REQUEST)
				throw new IOException("This is not a SSH_MSG_GLOBAL_REQUEST! (" + packet_type + ")");

			this.requestName = tr.readString();
			boolean wantReply = tr.readBoolean();

			this.hostKeys = new ArrayList<byte[]>();
			while (tr.remain() != 0) {
				hostKeys.add(tr.readByteString());
			}

			this.signatures = null;
		}
	}

	public byte[] getPayload()
	{
		if (requestName == null || hostKeys == null)
			throw new IllegalStateException("Cannot generate payload from a response packet");

		TypesWriter tw = new TypesWriter();
		tw.writeByte(Packets.SSH_MSG_GLOBAL_REQUEST);
		tw.writeString(requestName);
		tw.writeBoolean(true);

		for (byte[] hostKey : hostKeys) {
			tw.writeString(hostKey, 0, hostKey.length);
		}

		return tw.getBytes();
	}

	public List<byte[]> getHostkeys()
	{
		return hostKeys;
	}

	public List<byte[]> getSignatures()
	{
		return signatures;
	}

	public String getRequestName()
	{
		return requestName;
	}
}

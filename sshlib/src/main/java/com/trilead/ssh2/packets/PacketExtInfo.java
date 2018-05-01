package com.trilead.ssh2.packets;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Packet format described here:
 * https://tools.ietf.org/html/draft-ietf-curdle-ssh-ext-info-15#section-2.3
 */
public class PacketExtInfo
{
	private byte[] payload;

	private final Map<String, String> extNameToValue;

	public byte[] getPayload()
	{
		if (payload == null)
		{
			TypesWriter tw = new TypesWriter();
			tw.writeByte(Packets.SSH_MSG_EXT_INFO);
			tw.writeUINT32(extNameToValue.size());
			for (Entry<String, String> nameAndValue : extNameToValue.entrySet())
			{
				tw.writeString(nameAndValue.getKey());
				tw.writeString(nameAndValue.getValue());
			}
			payload = tw.getBytes();
		}
		return payload;
	}

	public Map<String, String> getExtNameToValue()
	{
		return extNameToValue;
	}

	public PacketExtInfo(byte payload[], int off, int len) throws IOException
	{
		this.payload = new byte[len];
		System.arraycopy(payload, off, this.payload, 0, len);

		TypesReader tr = new TypesReader(payload, off, len);
		int packet_type = tr.readByte();
		if (packet_type != Packets.SSH_MSG_EXT_INFO)
		{
			throw new IOException("This is not a SSH_MSG_EXT_INFO! ("
					+ packet_type + ")");
		}

		// Type has dynamic number of fields
		// First int tells us how many pairs to expect
		int numExtensions = tr.readUINT32();
		Map<String, String> extNameToValue_ = new HashMap<>(numExtensions);
		for (int i = 0; i < numExtensions; i++)
		{
			String name = tr.readString();
			String value = tr.readString();
			extNameToValue_.put(name, value);
		}
		extNameToValue = Collections.unmodifiableMap(extNameToValue_);

		if (tr.remain() != 0)
		{
			throw new IOException("Padding in SSH_MSG_EXT_INFO packet!");
		}
	}

	public PacketExtInfo(Map<String, String> extNameToValue)
	{
		this.extNameToValue = Collections.unmodifiableMap(new HashMap<>(extNameToValue));
	}
}

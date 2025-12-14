package com.trilead.ssh2.transport;

import java.io.IOException;
import java.util.Arrays;

/**
 * Exception thrown when key exchange negotiation fails due to incompatible proposals.
 * Contains the client and server proposals for debugging purposes.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: NegotiateException.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 */
public class NegotiateException extends IOException
{
	private static final long serialVersionUID = 3689910669428143157L;

	private final KexParameters clientProposal;
	private final KexParameters serverProposal;

	public NegotiateException() {
		this(null, null);
	}

	public NegotiateException(KexParameters clientProposal, KexParameters serverProposal) {
		super(buildMessage(clientProposal, serverProposal));
		this.clientProposal = clientProposal;
		this.serverProposal = serverProposal;
	}

	public KexParameters getClientProposal() {
		return clientProposal;
	}

	public KexParameters getServerProposal() {
		return serverProposal;
	}

	private static String buildMessage(KexParameters client, KexParameters server) {
		StringBuilder sb = new StringBuilder("Cannot negotiate, proposals do not match.");
		if (client != null && server != null) {
			sb.append("\n\nClient proposal:");
			appendProposal(sb, client);
			sb.append("\n\nServer proposal:");
			appendProposal(sb, server);
		}
		return sb.toString();
	}

	private static void appendProposal(StringBuilder sb, KexParameters params) {
		if (params == null) {
			sb.append("\n  (null)");
			return;
		}
		sb.append("\n  kex_algorithms: ").append(Arrays.toString(params.kex_algorithms));
		sb.append("\n  server_host_key_algorithms: ").append(Arrays.toString(params.server_host_key_algorithms));
		sb.append("\n  encryption_algorithms_client_to_server: ").append(Arrays.toString(params.encryption_algorithms_client_to_server));
		sb.append("\n  encryption_algorithms_server_to_client: ").append(Arrays.toString(params.encryption_algorithms_server_to_client));
		sb.append("\n  mac_algorithms_client_to_server: ").append(Arrays.toString(params.mac_algorithms_client_to_server));
		sb.append("\n  mac_algorithms_server_to_client: ").append(Arrays.toString(params.mac_algorithms_server_to_client));
		sb.append("\n  compression_algorithms_client_to_server: ").append(Arrays.toString(params.compression_algorithms_client_to_server));
		sb.append("\n  compression_algorithms_server_to_client: ").append(Arrays.toString(params.compression_algorithms_server_to_client));
		sb.append("\n  languages_client_to_server: ").append(Arrays.toString(params.languages_client_to_server));
		sb.append("\n  languages_server_to_client: ").append(Arrays.toString(params.languages_server_to_client));
	}
}

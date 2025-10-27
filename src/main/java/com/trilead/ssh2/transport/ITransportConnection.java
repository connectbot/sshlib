package com.trilead.ssh2.transport;

import java.io.IOException;

/**
 * Interface for SSH transport layer operations.
 * <p>
 * This interface defines the minimal contract needed by components like ChannelManager
 * to interact with the SSH transport layer without depending on the concrete
 * TransportManager implementation.
 * <p>
 * This design allows for:
 * <ul>
 * <li>Easy mocking in unit tests
 * <li>Potential alternative transport implementations
 * <li>Clear separation of concerns between channel and transport layers
 * </ul>
 *
 * @author ConnectBot SSH Library
 * @see TransportManager
 * @see MessageHandler
 */
public interface ITransportConnection {

	/**
	 * Register a message handler for a range of packet types.
	 * <p>
	 * The handler will be called for all packets with types in the range [low, high] (inclusive).
	 *
	 * @param mh   the message handler
	 * @param low  the lowest packet type to handle
	 * @param high the highest packet type to handle
	 */
	void registerMessageHandler(MessageHandler mh, int low, int high);

	/**
	 * Send a message synchronously over the transport connection.
	 * <p>
	 * This method blocks until the message is sent or an error occurs.
	 *
	 * @param msg the message payload to send
	 * @throws IOException if an I/O error occurs during sending
	 */
	void sendMessage(byte[] msg) throws IOException;

	/**
	 * Send a message asynchronously over the transport connection.
	 * <p>
	 * This method queues the message for sending and returns immediately.
	 * The message will be sent by a background thread.
	 *
	 * @param msg the message payload to send
	 * @throws IOException if an I/O error occurs during queueing
	 */
	void sendAsynchronousMessage(byte[] msg) throws IOException;

	/**
	 * Get the estimated packet overhead for window size calculations.
	 * <p>
	 * This overhead includes the SSH packet header, MAC, and encryption padding.
	 * It is used by the channel layer to determine how much data can be sent
	 * within the remote window size.
	 *
	 * @return the estimated overhead in bytes
	 */
	int getPacketOverheadEstimate();
}

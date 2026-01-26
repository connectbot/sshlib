/*
 * Copyright 2025 Kenny Root
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

package org.connectbot.sshlib.transport

/**
 * Transport abstraction for SSH connections.
 *
 * This interface allows SSH to work over any byte stream transport,
 * not just TCP sockets. Implementations could include:
 * - TCP sockets (via Ktor or other libraries)
 * - Unix domain sockets
 * - Serial ports
 * - Custom transport layers
 */
interface Transport {
    /**
     * Read exactly [count] bytes from the transport.
     *
     * @param count Number of bytes to read
     * @return ByteArray containing exactly [count] bytes
     * @throws TransportException if the connection is closed or an error occurs
     */
    suspend fun read(count: Int): ByteArray

    /**
     * Write all bytes to the transport.
     *
     * @param data Bytes to write
     * @throws TransportException if the connection is closed or an error occurs
     */
    suspend fun write(data: ByteArray)

    /**
     * Close the transport connection.
     */
    suspend fun close()

    /**
     * Check if the transport is still connected.
     */
    val isConnected: Boolean
}

/**
 * Exception thrown when transport operations fail.
 */
class TransportException(message: String, cause: Throwable? = null) : Exception(message, cause)

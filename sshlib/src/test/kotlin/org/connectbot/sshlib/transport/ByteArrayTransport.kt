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

import java.io.ByteArrayOutputStream

/**
 * Transport implementation backed by byte arrays.
 *
 * Useful for testing with captured protocol data or for in-memory
 * SSH protocol handling.
 *
 * @param inputData Initial data available for reading
 */
class ByteArrayTransport(
    inputData: ByteArray = byteArrayOf()
) : Transport {

    private var readBuffer = inputData
    private var readPosition = 0
    private val writeBuffer = ByteArrayOutputStream()
    private var connected = true

    override suspend fun read(count: Int): ByteArray {
        if (!connected) {
            throw TransportException("Transport is closed")
        }

        val remaining = readBuffer.size - readPosition
        if (remaining < count) {
            throw TransportException("Not enough data: requested $count bytes, only $remaining available")
        }

        val result = readBuffer.copyOfRange(readPosition, readPosition + count)
        readPosition += count
        return result
    }

    override suspend fun write(data: ByteArray) {
        if (!connected) {
            throw TransportException("Transport is closed")
        }
        writeBuffer.write(data)
    }

    override suspend fun close() {
        connected = false
    }

    override val isConnected: Boolean
        get() = connected

    /**
     * Get all data that has been written to this transport.
     */
    fun getWrittenData(): ByteArray = writeBuffer.toByteArray()

    /**
     * Add more data to the read buffer.
     */
    fun appendInputData(data: ByteArray) {
        val newBuffer = ByteArray(readBuffer.size - readPosition + data.size)
        System.arraycopy(readBuffer, readPosition, newBuffer, 0, readBuffer.size - readPosition)
        System.arraycopy(data, 0, newBuffer, readBuffer.size - readPosition, data.size)
        readBuffer = newBuffer
        readPosition = 0
    }

    /**
     * Number of bytes remaining to be read.
     */
    val bytesRemaining: Int
        get() = readBuffer.size - readPosition

    /**
     * Check if all input data has been consumed.
     */
    val isInputExhausted: Boolean
        get() = readPosition >= readBuffer.size
}

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

package org.connectbot.sshlib.client.sftp

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Dispatches SFTP requests and routes responses back to waiting coroutines.
 *
 * Each outbound request gets a unique request ID. A background read loop
 * parses incoming SFTP packets and completes the matching deferred.
 */
internal class SftpDispatcher(private val packetIO: SftpPacketIO) {
    private val nextRequestId = AtomicInteger(1)
    private val pending = ConcurrentHashMap<Int, CompletableDeferred<SftpRawPacket>>()
    private val writeMutex = Mutex()
    private var readJob: Job? = null

    /**
     * Send an SFTP request and wait for the matching response.
     *
     * @param type SFTP message type
     * @param payload Request payload (without request ID — it will be prepended)
     * @param timeoutMs Maximum time to wait for a response
     * @return The raw response packet
     */
    suspend fun request(type: Int, payload: ByteArray, timeoutMs: Long = 30_000L): SftpRawPacket {
        val requestId = nextRequestId.getAndIncrement()
        val deferred = CompletableDeferred<SftpRawPacket>()
        pending[requestId] = deferred

        try {
            // Prepend request ID to payload
            val fullPayload = ByteBuffer.allocate(4 + payload.size)
            fullPayload.putInt(requestId)
            fullPayload.put(payload)

            writeMutex.withLock {
                packetIO.writePacket(type, fullPayload.array())
            }

            return withTimeout(timeoutMs) {
                deferred.await()
            }
        } catch (e: Exception) {
            pending.remove(requestId)
            throw e
        }
    }

    /**
     * Send an SFTP packet without a request ID (used for INIT).
     */
    suspend fun writeRaw(type: Int, payload: ByteArray) {
        writeMutex.withLock {
            packetIO.writePacket(type, payload)
        }
    }

    /**
     * Read a single raw packet (used for VERSION response during init).
     */
    suspend fun readRaw(): SftpRawPacket = packetIO.readPacket()

    /**
     * Start the background read loop that routes responses to waiting callers.
     */
    fun startReadLoop(scope: CoroutineScope): Job {
        val job = scope.launch {
            try {
                while (true) {
                    val packet = packetIO.readPacket()

                    // Extract request ID from first 4 bytes of payload
                    if (packet.payload.size < 4) {
                        logger.warn("SFTP packet type {} with payload too short for request ID", packet.type)
                        continue
                    }

                    val requestId = ByteBuffer.wrap(packet.payload, 0, 4).int
                    val responsePayload = packet.payload.copyOfRange(4, packet.payload.size)
                    val responsePacket = SftpRawPacket(packet.type, responsePayload)

                    val deferred = pending.remove(requestId)
                    if (deferred != null) {
                        deferred.complete(responsePacket)
                    } else {
                        logger.warn("SFTP response for unknown request ID {}", requestId)
                    }
                }
            } catch (e: SftpProtocolException) {
                logger.debug("SFTP channel closed: {}", e.message)
                // Complete all pending requests with the error
                val error = e
                pending.values.forEach { it.completeExceptionally(error) }
                pending.clear()
            } catch (e: Exception) {
                logger.debug("SFTP read loop ended: {}", e.message)
                pending.values.forEach { it.completeExceptionally(e) }
                pending.clear()
            }
        }
        readJob = job
        return job
    }

    fun stop() {
        readJob?.cancel()
        pending.values.forEach {
            it.completeExceptionally(SftpProtocolException("SFTP session closed"))
        }
        pending.clear()
    }

    companion object {
        private val logger = LoggerFactory.getLogger(SftpDispatcher::class.java)
    }
}

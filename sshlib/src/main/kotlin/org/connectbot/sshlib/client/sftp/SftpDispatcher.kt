/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
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
import org.connectbot.sshlib.SftpResult
import org.connectbot.sshlib.protocol.SftpStateMachine
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
internal class SftpDispatcher(
    private val packetIO: SftpPacketTransport,
    private val stateMachine: SftpStateMachine = SftpStateMachine(),
) {
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
    suspend fun request(type: Int, payload: ByteArray, timeoutMs: Long = 30_000L): SftpResult<SftpRawPacket> = request(type, payload, timeoutMs) { action ->
        action()
        true
    }

    /**
     * Admit and write a request as one state-machine action, then await its response
     * after the state-machine serialization point has been released.
     */
    suspend fun request(
        type: Int,
        payload: ByteArray,
        timeoutMs: Long = 30_000L,
        authorize: suspend (suspend () -> Unit) -> Boolean,
    ): SftpResult<SftpRawPacket> {
        var requestId = 0
        var deferred: CompletableDeferred<SftpRawPacket>? = null
        var writeResult: SftpResult<Unit>? = null

        val authorized = authorize {
            requestId = nextRequestId.getAndIncrement()
            deferred = CompletableDeferred<SftpRawPacket>().also { pending[requestId] = it }

            val fullPayload = ByteBuffer.allocate(4 + payload.size)
            fullPayload.putInt(requestId)
            fullPayload.put(payload)

            writeResult = writeMutex.withLock {
                packetIO.writePacket(type, fullPayload.array())
            }
        }
        if (!authorized) {
            return SftpResult.ProtocolError("SFTP session is not ready")
        }

        val response = deferred
            ?: return SftpResult.ProtocolError("Authorized SFTP request did not run its action")
        val result = writeResult
            ?: return SftpResult.ProtocolError("Authorized SFTP request did not produce a write result")
        if (result is SftpResult.IoError) {
            pending.remove(requestId)
            return result
        }
        if (result is SftpResult.ProtocolError) {
            pending.remove(requestId)
            return result
        }
        if (result is SftpResult.ServerError) {
            pending.remove(requestId)
            return result
        }

        return try {
            val packet = withTimeout(timeoutMs) {
                response.await()
            }
            SftpResult.Success(packet)
        } catch (e: Exception) {
            pending.remove(requestId)
            SftpResult.IoError(e)
        }
    }

    /**
     * Send an SFTP packet without a request ID (used for INIT). Just
     * forwards the framing-layer result.
     */
    suspend fun writeRaw(type: Int, payload: ByteArray): SftpResult<Unit> = writeMutex.withLock {
        packetIO.writePacket(type, payload)
    }

    /**
     * Read a single raw packet (used for VERSION response during init).
     */
    suspend fun readRaw(): SftpResult<SftpRawPacket> {
        val result = packetIO.readPacket()
        if (result is SftpResult.Success && result.value.type == SSH_FXP_VERSION) {
            stateMachine.receiveVersion { }
        }
        return result
    }

    /**
     * Start the background read loop that routes responses to waiting callers.
     */
    fun startReadLoop(scope: CoroutineScope): Job {
        val job = scope.launch {
            try {
                loop@ while (true) {
                    val packet = when (val result = packetIO.readPacket()) {
                        is SftpResult.Success -> result.value

                        is SftpResult.IoError -> {
                            logger.debug("SFTP read loop ended: {}", result.cause.message)
                            stateMachine.disconnect { failPending(result.cause) }
                            break@loop
                        }

                        is SftpResult.ProtocolError -> {
                            logger.debug("SFTP channel closed: {}", result.message)
                            val err = SftpProtocolException(result.message)
                            stateMachine.disconnect { failPending(err) }
                            break@loop
                        }

                        is SftpResult.ServerError -> {
                            logger.warn("Unexpected ServerError from packet framing: code={}", result.statusCode)
                            stateMachine.disconnect {
                                failPending(SftpProtocolException("Unexpected SFTP framing server error"))
                            }
                            break@loop
                        }
                    }

                    // Extract request ID from first 4 bytes of payload
                    if (packet.payload.size < 4) {
                        logger.warn("SFTP packet type {} with payload too short for request ID", packet.type)
                        continue
                    }

                    // Notify state machine directly of incoming packet
                    when (packet.type) {
                        SSH_FXP_STATUS -> stateMachine.receiveStatus { }
                        SSH_FXP_HANDLE -> stateMachine.receiveHandle { }
                        SSH_FXP_DATA -> stateMachine.receiveData { }
                        SSH_FXP_NAME -> stateMachine.receiveName { }
                        SSH_FXP_ATTRS -> stateMachine.receiveAttrs { }
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
            } catch (e: Exception) {
                logger.debug("SFTP read loop ended unexpectedly: {}", e.message)
                stateMachine.disconnect { failPending(e) }
            }
        }
        readJob = job
        return job
    }

    fun stop() {
        readJob?.cancel()
        failPending(SftpProtocolException("SFTP session closed"))
    }

    private fun failPending(cause: Throwable) {
        pending.values.forEach { it.completeExceptionally(cause) }
        pending.clear()
    }

    companion object {
        private val logger = LoggerFactory.getLogger(SftpDispatcher::class.java)

        private const val SSH_FXP_VERSION = 2
        private const val SSH_FXP_STATUS = 101
        private const val SSH_FXP_HANDLE = 102
        private const val SSH_FXP_DATA = 103
        private const val SSH_FXP_NAME = 104
        private const val SSH_FXP_ATTRS = 105
    }
}

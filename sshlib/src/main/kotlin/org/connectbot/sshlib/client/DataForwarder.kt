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

package org.connectbot.sshlib.client

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.cancel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import kotlin.coroutines.cancellation.CancellationException

/**
 * Bidirectional data forwarder between a TCP connection (Ktor channels) and an SSH
 * forwarding channel.
 *
 * Runs two coroutines: TCP→SSH and SSH→TCP, cancelling both when either side closes.
 */
internal class DataForwarder(
    private val scope: CoroutineScope,
    private val sshChannel: ForwardingChannel,
    private val tcpRead: ByteReadChannel,
    private val tcpWrite: ByteWriteChannel,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(DataForwarder::class.java)
        private const val BUFFER_SIZE = 32 * 1024
    }

    private var job: Job? = null

    fun start() {
        job = scope.launch {
            try {
                coroutineScope {
                    val tcpToSsh = launch { forwardTcpToSsh() }
                    val sshToTcp = launch { forwardSshToTcp() }

                    // When either direction finishes, cancel the other
                    awaitFirst(tcpToSsh, sshToTcp)
                }
            } catch (_: CancellationException) {
                // Normal shutdown
            } catch (e: Exception) {
                logger.debug("DataForwarder ended: ${e.message}")
            } finally {
                cleanup()
            }
        }
    }

    private suspend fun awaitFirst(vararg jobs: Job) {
        try {
            while (jobs.all { it.isActive }) {
                delay(50)
            }
        } finally {
            jobs.forEach { it.cancel() }
        }
    }

    private suspend fun forwardTcpToSsh() {
        val buffer = ByteArray(BUFFER_SIZE)
        try {
            while (!tcpRead.isClosedForRead) {
                val bytesRead = tcpRead.readAvailable(buffer)
                if (bytesRead == -1) break
                if (bytesRead > 0) {
                    sshChannel.sendData(buffer.copyOf(bytesRead))
                }
            }
            sshChannel.sendEof()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger.debug("TCP→SSH ended: ${e.message}")
        }
    }

    private suspend fun forwardSshToTcp() {
        try {
            for (data in sshChannel.incomingData) {
                tcpWrite.writeFully(data, 0, data.size)
                tcpWrite.flush()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger.debug("SSH→TCP ended: ${e.message}")
        }
    }

    private suspend fun cleanup() {
        try {
            tcpWrite.flushAndClose()
        } catch (_: Exception) {}
        try {
            tcpRead.cancel()
        } catch (_: Exception) {}
        try {
            sshChannel.close()
        } catch (_: Exception) {}
    }

    suspend fun stop() {
        job?.cancelAndJoin()
    }
}

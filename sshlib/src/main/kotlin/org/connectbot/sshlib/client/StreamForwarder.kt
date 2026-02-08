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

import io.ktor.utils.io.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.slf4j.LoggerFactory

internal class StreamForwarder private constructor(
    private val dataForwarder: DataForwarder
) : org.connectbot.sshlib.StreamForwarder {
    companion object {
        private val logger = LoggerFactory.getLogger(StreamForwarder::class.java)

        suspend fun create(
            connection: SshConnection,
            readChannel: ByteReadChannel,
            writeChannel: ByteWriteChannel,
            remoteHost: String,
            remotePort: Int,
            originAddr: String = "127.0.0.1",
            originPort: Int = 0
        ): StreamForwarder? {
            val sshChannel = connection.openDirectTcpipChannel(
                remoteHost, remotePort, originAddr, originPort
            )
            if (sshChannel == null) {
                logger.warn("Failed to open direct-tcpip channel for $remoteHost:$remotePort")
                return null
            }

            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            val forwarder = DataForwarder(scope, sshChannel, readChannel, writeChannel)
            val streamForwarder = StreamForwarder(forwarder)
            forwarder.start()
            return streamForwarder
        }
    }

    private var _isActive = true

    override val isActive: Boolean get() = _isActive

    override suspend fun stop() {
        if (!_isActive) return
        _isActive = false
        dataForwarder.stop()
    }
}

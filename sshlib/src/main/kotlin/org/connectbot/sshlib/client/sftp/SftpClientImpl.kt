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

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import org.connectbot.sshlib.SftpAttributes
import org.connectbot.sshlib.SftpClient
import org.connectbot.sshlib.SftpDirectoryEntry
import org.connectbot.sshlib.SftpFileHandle
import org.connectbot.sshlib.SftpOpenFlag
import org.connectbot.sshlib.SftpResult
import org.connectbot.sshlib.SftpStatusCode
import org.connectbot.sshlib.SshSession
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Internal implementation of [SftpClient].
 *
 * SFTP message types (draft-ietf-secsh-filexfer-02 section 3):
 */
internal class SftpClientImpl private constructor(
    private val session: SshSession,
    private val dispatcher: SftpDispatcher,
    private val readJob: Job,
    override val protocolVersion: Int,
) : SftpClient {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var closed = false

    override val isOpen: Boolean get() = !closed && session.isOpen

    // --- File I/O ---

    override suspend fun open(path: String, flags: Set<SftpOpenFlag>, attrs: SftpAttributes): SftpResult<SftpFileHandle> {
        val pflags = flags.fold(0) { acc, flag -> acc or flag.value }
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val attrsBytes = SftpFileAttributes.encode(attrs)

        val payload = ByteBuffer.allocate(4 + pathBytes.size + 4 + attrsBytes.size)
        putString(payload, pathBytes)
        payload.putInt(pflags)
        payload.put(attrsBytes)

        return dispatchRequest(SSH_FXP_OPEN, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_HANDLE -> SftpResult.Success(SftpFileHandle(extractString(ByteBuffer.wrap(response.payload))))
                SSH_FXP_STATUS -> decodeStatusError(response.payload)
                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for OPEN")
            }
        }
    }

    override suspend fun close(handle: SftpFileHandle): SftpResult<Unit> {
        val payload = ByteBuffer.allocate(4 + handle.handle.size)
        putString(payload, handle.handle)

        return dispatchRequest(SSH_FXP_CLOSE, payload.array()) { response ->
            if (response.type == SSH_FXP_STATUS) {
                val status = decodeStatus(response.payload)
                if (status == SftpStatusCode.OK) {
                    SftpResult.Success(Unit)
                } else {
                    decodeStatusError(response.payload)
                }
            } else {
                SftpResult.Success(Unit)
            }
        }
    }

    override suspend fun read(handle: SftpFileHandle, offset: Long, length: Int): SftpResult<ByteArray?> {
        val payload = ByteBuffer.allocate(4 + handle.handle.size + 8 + 4)
        putString(payload, handle.handle)
        payload.putLong(offset)
        payload.putInt(length)

        return dispatchRequest(SSH_FXP_READ, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_DATA -> SftpResult.Success(extractString(ByteBuffer.wrap(response.payload)))

                SSH_FXP_STATUS -> {
                    val status = decodeStatus(response.payload)
                    if (status == SftpStatusCode.EOF) {
                        SftpResult.Success(null)
                    } else {
                        decodeStatusError(response.payload)
                    }
                }

                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for READ")
            }
        }
    }

    override suspend fun write(handle: SftpFileHandle, offset: Long, data: ByteArray): SftpResult<Unit> {
        val payload = ByteBuffer.allocate(4 + handle.handle.size + 8 + 4 + data.size)
        putString(payload, handle.handle)
        payload.putLong(offset)
        putString(payload, data)

        return dispatchStatusRequest(SSH_FXP_WRITE, payload.array())
    }

    // --- Stat operations ---

    override suspend fun stat(path: String): SftpResult<SftpAttributes> = statRequest(SSH_FXP_STAT, path)

    override suspend fun lstat(path: String): SftpResult<SftpAttributes> = statRequest(SSH_FXP_LSTAT, path)

    private suspend fun statRequest(type: Int, path: String): SftpResult<SftpAttributes> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchRequest(type, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_ATTRS -> SftpResult.Success(SftpFileAttributes.decode(ByteBuffer.wrap(response.payload)))
                SSH_FXP_STATUS -> decodeStatusError(response.payload)
                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for STAT")
            }
        }
    }

    override suspend fun fstat(handle: SftpFileHandle): SftpResult<SftpAttributes> {
        val payload = ByteBuffer.allocate(4 + handle.handle.size)
        putString(payload, handle.handle)

        return dispatchRequest(SSH_FXP_FSTAT, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_ATTRS -> SftpResult.Success(SftpFileAttributes.decode(ByteBuffer.wrap(response.payload)))
                SSH_FXP_STATUS -> decodeStatusError(response.payload)
                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for FSTAT")
            }
        }
    }

    override suspend fun setstat(path: String, attrs: SftpAttributes): SftpResult<Unit> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val attrsBytes = SftpFileAttributes.encode(attrs)
        val payload = ByteBuffer.allocate(4 + pathBytes.size + attrsBytes.size)
        putString(payload, pathBytes)
        payload.put(attrsBytes)

        return dispatchStatusRequest(SSH_FXP_SETSTAT, payload.array())
    }

    override suspend fun fsetstat(handle: SftpFileHandle, attrs: SftpAttributes): SftpResult<Unit> {
        val attrsBytes = SftpFileAttributes.encode(attrs)
        val payload = ByteBuffer.allocate(4 + handle.handle.size + attrsBytes.size)
        putString(payload, handle.handle)
        payload.put(attrsBytes)

        return dispatchStatusRequest(SSH_FXP_FSETSTAT, payload.array())
    }

    // --- Directory operations ---

    override suspend fun opendir(path: String): SftpResult<SftpFileHandle> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchRequest(SSH_FXP_OPENDIR, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_HANDLE -> SftpResult.Success(SftpFileHandle(extractString(ByteBuffer.wrap(response.payload))))
                SSH_FXP_STATUS -> decodeStatusError(response.payload)
                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for OPENDIR")
            }
        }
    }

    override suspend fun readdir(handle: SftpFileHandle): SftpResult<List<SftpDirectoryEntry>?> {
        val payload = ByteBuffer.allocate(4 + handle.handle.size)
        putString(payload, handle.handle)

        return dispatchRequest(SSH_FXP_READDIR, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_NAME -> SftpResult.Success(decodeName(response.payload))

                SSH_FXP_STATUS -> {
                    val status = decodeStatus(response.payload)
                    if (status == SftpStatusCode.EOF) {
                        SftpResult.Success(null)
                    } else {
                        decodeStatusError(response.payload)
                    }
                }

                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for READDIR")
            }
        }
    }

    override suspend fun mkdir(path: String, attrs: SftpAttributes): SftpResult<Unit> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val attrsBytes = SftpFileAttributes.encode(attrs)
        val payload = ByteBuffer.allocate(4 + pathBytes.size + attrsBytes.size)
        putString(payload, pathBytes)
        payload.put(attrsBytes)

        return dispatchStatusRequest(SSH_FXP_MKDIR, payload.array())
    }

    override suspend fun rmdir(path: String): SftpResult<Unit> = simplePathRequest(SSH_FXP_RMDIR, path)

    // --- File management ---

    override suspend fun remove(path: String): SftpResult<Unit> = simplePathRequest(SSH_FXP_REMOVE, path)

    override suspend fun rename(oldPath: String, newPath: String): SftpResult<Unit> {
        val oldBytes = oldPath.toByteArray(StandardCharsets.UTF_8)
        val newBytes = newPath.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + oldBytes.size + 4 + newBytes.size)
        putString(payload, oldBytes)
        putString(payload, newBytes)

        return dispatchStatusRequest(SSH_FXP_RENAME, payload.array())
    }

    // --- Path operations ---

    override suspend fun realpath(path: String): SftpResult<String> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchRequest(SSH_FXP_REALPATH, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_NAME -> {
                    val entries = decodeName(response.payload)
                    val filename = entries.firstOrNull()?.filename
                    if (filename != null) {
                        SftpResult.Success(filename)
                    } else {
                        SftpResult.ProtocolError("REALPATH returned empty NAME")
                    }
                }

                SSH_FXP_STATUS -> decodeStatusError(response.payload)

                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for REALPATH")
            }
        }
    }

    override suspend fun readlink(path: String): SftpResult<String> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchRequest(SSH_FXP_READLINK, payload.array()) { response ->
            when (response.type) {
                SSH_FXP_NAME -> {
                    val entries = decodeName(response.payload)
                    val filename = entries.firstOrNull()?.filename
                    if (filename != null) {
                        SftpResult.Success(filename)
                    } else {
                        SftpResult.ProtocolError("READLINK returned empty NAME")
                    }
                }

                SSH_FXP_STATUS -> decodeStatusError(response.payload)

                else -> SftpResult.ProtocolError("Unexpected response type ${response.type} for READLINK")
            }
        }
    }

    override suspend fun symlink(targetPath: String, linkPath: String): SftpResult<Unit> {
        // Note: OpenSSH has a known bug where symlink arguments are reversed
        // from the spec. The spec says (targetpath, linkpath) but OpenSSH
        // expects (linkpath, targetpath). We follow the OpenSSH convention
        // since it's the most common server implementation.
        val linkBytes = linkPath.toByteArray(StandardCharsets.UTF_8)
        val targetBytes = targetPath.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + linkBytes.size + 4 + targetBytes.size)
        putString(payload, linkBytes)
        putString(payload, targetBytes)

        return dispatchStatusRequest(SSH_FXP_SYMLINK, payload.array())
    }

    override fun close() {
        if (closed) return
        closed = true
        dispatcher.stop()
        session.close()
    }

    // --- Internal helpers ---

    /**
     * Send a request and map the response.
     */
    private suspend fun <T> dispatchRequest(
        type: Int,
        payload: ByteArray,
        map: (SftpRawPacket) -> SftpResult<T>,
    ): SftpResult<T> = when (val result = dispatcher.request(type, payload)) {
        is SftpResult.Success -> map(result.value)
        is SftpResult.ServerError -> result
        is SftpResult.ProtocolError -> result
        is SftpResult.IoError -> result
    }

    /**
     * Send a request that expects SSH_FXP_STATUS with OK.
     */
    private suspend fun dispatchStatusRequest(type: Int, payload: ByteArray): SftpResult<Unit> = dispatchRequest(type, payload) { response ->
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payload)
            if (status == SftpStatusCode.OK) {
                SftpResult.Success(Unit)
            } else {
                decodeStatusError(response.payload)
            }
        } else {
            SftpResult.Success(Unit)
        }
    }

    private suspend fun simplePathRequest(type: Int, path: String): SftpResult<Unit> {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        return dispatchStatusRequest(type, payload.array())
    }

    companion object {
        private val logger = LoggerFactory.getLogger(SftpClientImpl::class.java)

        // SFTP message types
        private const val SSH_FXP_INIT = 1
        private const val SSH_FXP_VERSION = 2
        private const val SSH_FXP_OPEN = 3
        private const val SSH_FXP_CLOSE = 4
        private const val SSH_FXP_READ = 5
        private const val SSH_FXP_WRITE = 6
        private const val SSH_FXP_LSTAT = 7
        private const val SSH_FXP_FSTAT = 8
        private const val SSH_FXP_SETSTAT = 9
        private const val SSH_FXP_FSETSTAT = 10
        private const val SSH_FXP_OPENDIR = 11
        private const val SSH_FXP_READDIR = 12
        private const val SSH_FXP_REMOVE = 13
        private const val SSH_FXP_MKDIR = 14
        private const val SSH_FXP_RMDIR = 15
        private const val SSH_FXP_REALPATH = 16
        private const val SSH_FXP_STAT = 17
        private const val SSH_FXP_RENAME = 18
        private const val SSH_FXP_READLINK = 19
        private const val SSH_FXP_SYMLINK = 20

        private const val SSH_FXP_STATUS = 101
        private const val SSH_FXP_HANDLE = 102
        private const val SSH_FXP_DATA = 103
        private const val SSH_FXP_NAME = 104
        private const val SSH_FXP_ATTRS = 105

        private const val SFTP_VERSION = 3

        /**
         * Create an SFTP client by performing the INIT/VERSION handshake.
         */
        suspend fun create(session: SshSession): SftpResult<SftpClient> {
            val packetIO = SftpPacketIO(session)
            val dispatcher = SftpDispatcher(packetIO)

            // Send SSH_FXP_INIT
            val initPayload = ByteBuffer.allocate(4)
            initPayload.putInt(SFTP_VERSION)
            when (val w = dispatcher.writeRaw(SSH_FXP_INIT, initPayload.array())) {
                is SftpResult.Success -> {}
                is SftpResult.ServerError -> return w
                is SftpResult.ProtocolError -> return w
                is SftpResult.IoError -> return w
            }

            // Read SSH_FXP_VERSION
            val versionPacket = when (val r = dispatcher.readRaw()) {
                is SftpResult.Success -> r.value
                is SftpResult.ServerError -> return r
                is SftpResult.ProtocolError -> return r
                is SftpResult.IoError -> return r
            }
            if (versionPacket.type != SSH_FXP_VERSION) {
                return SftpResult.ProtocolError(
                    "Expected SSH_FXP_VERSION (2), got ${versionPacket.type}",
                )
            }
            if (versionPacket.payload.size < 4) {
                return SftpResult.ProtocolError("SSH_FXP_VERSION payload too short")
            }
            val serverVersion = ByteBuffer.wrap(versionPacket.payload, 0, 4).int
            val negotiatedVersion = minOf(SFTP_VERSION, serverVersion)
            logger.info("SFTP version negotiated: {} (server: {})", negotiatedVersion, serverVersion)

            // Start the background read loop
            val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            val readJob = dispatcher.startReadLoop(scope)

            return SftpResult.Success(SftpClientImpl(session, dispatcher, readJob, negotiatedVersion))
        }

        // --- Wire format helpers ---

        /** Write a length-prefixed string/byte array to a ByteBuffer. */
        private fun putString(buf: ByteBuffer, data: ByteArray) {
            buf.putInt(data.size)
            buf.put(data)
        }

        /** Read a length-prefixed string/byte array from a ByteBuffer. */
        private fun extractString(buf: ByteBuffer): ByteArray {
            val len = buf.int
            val data = ByteArray(len)
            buf.get(data)
            return data
        }

        /** Decode a STATUS response to get the status code. */
        private fun decodeStatus(payload: ByteArray): SftpStatusCode {
            if (payload.size < 4) return SftpStatusCode.FAILURE
            val code = ByteBuffer.wrap(payload, 0, 4).int
            return SftpStatusCode.fromCode(code)
        }

        /** Decode a STATUS response into an [SftpResult.ServerError]. */
        private fun decodeStatusError(payload: ByteArray): SftpResult.ServerError {
            val buf = ByteBuffer.wrap(payload)
            val code = if (buf.remaining() >= 4) buf.int else 4
            val statusCode = SftpStatusCode.fromCode(code)
            val message = if (buf.remaining() >= 4) {
                val msgBytes = extractString(buf)
                String(msgBytes, StandardCharsets.UTF_8)
            } else {
                statusCode.name
            }
            return SftpResult.ServerError(statusCode, message)
        }

        /** Decode a NAME response (used by readdir, realpath, readlink). */
        private fun decodeName(payload: ByteArray): List<SftpDirectoryEntry> {
            val buf = ByteBuffer.wrap(payload)
            val count = buf.int
            val entries = mutableListOf<SftpDirectoryEntry>()
            repeat(count) {
                val filename = String(extractString(buf), StandardCharsets.UTF_8)
                val longname = String(extractString(buf), StandardCharsets.UTF_8)
                val attrs = SftpFileAttributes.decode(buf)
                entries.add(SftpDirectoryEntry(filename, longname, attrs))
            }
            return entries
        }
    }
}

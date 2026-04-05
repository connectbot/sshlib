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
import org.connectbot.sshlib.SftpException
import org.connectbot.sshlib.SftpFileHandle
import org.connectbot.sshlib.SftpOpenFlag
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

    override suspend fun open(path: String, flags: Set<SftpOpenFlag>, attrs: SftpAttributes): SftpFileHandle {
        val pflags = flags.fold(0) { acc, flag -> acc or flag.value }
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val attrsBytes = SftpFileAttributes.encode(attrs)

        val payload = ByteBuffer.allocate(4 + pathBytes.size + 4 + attrsBytes.size)
        putString(payload, pathBytes)
        payload.putInt(pflags)
        payload.put(attrsBytes)

        val response = dispatcher.request(SSH_FXP_OPEN, payload.array())
        return when (response.type) {
            SSH_FXP_HANDLE -> SftpFileHandle(extractString(ByteBuffer.wrap(response.payload)))
            SSH_FXP_STATUS -> throw decodeStatusException(response.payload)
            else -> throw SftpProtocolException("Unexpected response type ${response.type} for OPEN")
        }
    }

    override suspend fun close(handle: SftpFileHandle) {
        val payload = ByteBuffer.allocate(4 + handle.handle.size)
        putString(payload, handle.handle)

        val response = dispatcher.request(SSH_FXP_CLOSE, payload.array())
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payload)
            if (status != SftpStatusCode.OK) throw decodeStatusException(response.payload)
        }
    }

    override suspend fun read(handle: SftpFileHandle, offset: Long, length: Int): ByteArray? {
        val payload = ByteBuffer.allocate(4 + handle.handle.size + 8 + 4)
        putString(payload, handle.handle)
        payload.putLong(offset)
        payload.putInt(length)

        val response = dispatcher.request(SSH_FXP_READ, payload.array())
        return when (response.type) {
            SSH_FXP_DATA -> extractString(ByteBuffer.wrap(response.payload))
            SSH_FXP_STATUS -> {
                val status = decodeStatus(response.payload)
                if (status == SftpStatusCode.EOF) null
                else throw decodeStatusException(response.payload)
            }
            else -> throw SftpProtocolException("Unexpected response type ${response.type} for READ")
        }
    }

    override suspend fun write(handle: SftpFileHandle, offset: Long, data: ByteArray) {
        val payload = ByteBuffer.allocate(4 + handle.handle.size + 8 + 4 + data.size)
        putString(payload, handle.handle)
        payload.putLong(offset)
        putString(payload, data)

        val response = dispatcher.request(SSH_FXP_WRITE, payload.array())
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payload)
            if (status != SftpStatusCode.OK) throw decodeStatusException(response.payload)
        }
    }

    // --- Stat operations ---

    override suspend fun stat(path: String): SftpAttributes {
        return statRequest(SSH_FXP_STAT, path)
    }

    override suspend fun lstat(path: String): SftpAttributes {
        return statRequest(SSH_FXP_LSTAT, path)
    }

    private suspend fun statRequest(type: Int, path: String): SftpAttributes {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        val response = dispatcher.request(type, payload.array())
        return when (response.type) {
            SSH_FXP_ATTRS -> SftpFileAttributes.decode(ByteBuffer.wrap(response.payload))
            SSH_FXP_STATUS -> throw decodeStatusException(response.payload)
            else -> throw SftpProtocolException("Unexpected response type ${response.type} for STAT")
        }
    }

    override suspend fun fstat(handle: SftpFileHandle): SftpAttributes {
        val payload = ByteBuffer.allocate(4 + handle.handle.size)
        putString(payload, handle.handle)

        val response = dispatcher.request(SSH_FXP_FSTAT, payload.array())
        return when (response.type) {
            SSH_FXP_ATTRS -> SftpFileAttributes.decode(ByteBuffer.wrap(response.payload))
            SSH_FXP_STATUS -> throw decodeStatusException(response.payload)
            else -> throw SftpProtocolException("Unexpected response type ${response.type} for FSTAT")
        }
    }

    override suspend fun setstat(path: String, attrs: SftpAttributes) {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val attrsBytes = SftpFileAttributes.encode(attrs)
        val payload = ByteBuffer.allocate(4 + pathBytes.size + attrsBytes.size)
        putString(payload, pathBytes)
        payload.put(attrsBytes)

        val response = dispatcher.request(SSH_FXP_SETSTAT, payload.array())
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payload)
            if (status != SftpStatusCode.OK) throw decodeStatusException(response.payload)
        }
    }

    override suspend fun fsetstat(handle: SftpFileHandle, attrs: SftpAttributes) {
        val attrsBytes = SftpFileAttributes.encode(attrs)
        val payload = ByteBuffer.allocate(4 + handle.handle.size + attrsBytes.size)
        putString(payload, handle.handle)
        payload.put(attrsBytes)

        val response = dispatcher.request(SSH_FXP_FSETSTAT, payload.array())
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payload)
            if (status != SftpStatusCode.OK) throw decodeStatusException(response.payload)
        }
    }

    // --- Directory operations ---

    override suspend fun opendir(path: String): SftpFileHandle {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        val response = dispatcher.request(SSH_FXP_OPENDIR, payload.array())
        return when (response.type) {
            SSH_FXP_HANDLE -> SftpFileHandle(extractString(ByteBuffer.wrap(response.payload)))
            SSH_FXP_STATUS -> throw decodeStatusException(response.payload)
            else -> throw SftpProtocolException("Unexpected response type ${response.type} for OPENDIR")
        }
    }

    override suspend fun readdir(handle: SftpFileHandle): List<SftpDirectoryEntry>? {
        val payload = ByteBuffer.allocate(4 + handle.handle.size)
        putString(payload, handle.handle)

        val response = dispatcher.request(SSH_FXP_READDIR, payload.array())
        return when (response.type) {
            SSH_FXP_NAME -> decodeName(response.payload)
            SSH_FXP_STATUS -> {
                val status = decodeStatus(response.payload)
                if (status == SftpStatusCode.EOF) null
                else throw decodeStatusException(response.payload)
            }
            else -> throw SftpProtocolException("Unexpected response type ${response.type} for READDIR")
        }
    }

    override suspend fun mkdir(path: String, attrs: SftpAttributes) {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val attrsBytes = SftpFileAttributes.encode(attrs)
        val payload = ByteBuffer.allocate(4 + pathBytes.size + attrsBytes.size)
        putString(payload, pathBytes)
        payload.put(attrsBytes)

        val response = dispatcher.request(SSH_FXP_MKDIR, payload.array())
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payload)
            if (status != SftpStatusCode.OK) throw decodeStatusException(response.payload)
        }
    }

    override suspend fun rmdir(path: String) {
        simplePathRequest(SSH_FXP_RMDIR, path)
    }

    // --- File management ---

    override suspend fun remove(path: String) {
        simplePathRequest(SSH_FXP_REMOVE, path)
    }

    override suspend fun rename(oldPath: String, newPath: String) {
        val oldBytes = oldPath.toByteArray(StandardCharsets.UTF_8)
        val newBytes = newPath.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + oldBytes.size + 4 + newBytes.size)
        putString(payload, oldBytes)
        putString(payload, newBytes)

        val response = dispatcher.request(SSH_FXP_RENAME, payload.array())
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payload)
            if (status != SftpStatusCode.OK) throw decodeStatusException(response.payload)
        }
    }

    // --- Path operations ---

    override suspend fun realpath(path: String): String {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        val response = dispatcher.request(SSH_FXP_REALPATH, payload.array())
        return when (response.type) {
            SSH_FXP_NAME -> {
                val entries = decodeName(response.payload)
                entries.firstOrNull()?.filename
                    ?: throw SftpProtocolException("REALPATH returned empty NAME")
            }
            SSH_FXP_STATUS -> throw decodeStatusException(response.payload)
            else -> throw SftpProtocolException("Unexpected response type ${response.type} for REALPATH")
        }
    }

    override suspend fun readlink(path: String): String {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        val response = dispatcher.request(SSH_FXP_READLINK, payload.array())
        return when (response.type) {
            SSH_FXP_NAME -> {
                val entries = decodeName(response.payload)
                entries.firstOrNull()?.filename
                    ?: throw SftpProtocolException("READLINK returned empty NAME")
            }
            SSH_FXP_STATUS -> throw decodeStatusException(response.payload)
            else -> throw SftpProtocolException("Unexpected response type ${response.type} for READLINK")
        }
    }

    override suspend fun symlink(targetPath: String, linkPath: String) {
        // Note: OpenSSH has a known bug where symlink arguments are reversed
        // from the spec. The spec says (targetpath, linkpath) but OpenSSH
        // expects (linkpath, targetpath). We follow the OpenSSH convention
        // since it's the most common server implementation.
        val linkBytes = linkPath.toByteArray(StandardCharsets.UTF_8)
        val targetBytes = targetPath.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + linkBytes.size + 4 + targetBytes.size)
        putString(payload, linkBytes)
        putString(payload, targetBytes)

        val response = dispatcher.request(SSH_FXP_SYMLINK, payload.array())
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payload)
            if (status != SftpStatusCode.OK) throw decodeStatusException(response.payload)
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        dispatcher.stop()
        session.close()
    }

    // --- Helpers ---

    private suspend fun simplePathRequest(type: Int, path: String) {
        val pathBytes = path.toByteArray(StandardCharsets.UTF_8)
        val payload = ByteBuffer.allocate(4 + pathBytes.size)
        putString(payload, pathBytes)

        val response = dispatcher.request(type, payload.array())
        if (response.type == SSH_FXP_STATUS) {
            val status = decodeStatus(response.payload)
            if (status != SftpStatusCode.OK) throw decodeStatusException(response.payload)
        }
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
        suspend fun create(session: SshSession): SftpClient {
            val packetIO = SftpPacketIO(session)
            val dispatcher = SftpDispatcher(packetIO)

            // Send SSH_FXP_INIT
            val initPayload = ByteBuffer.allocate(4)
            initPayload.putInt(SFTP_VERSION)
            dispatcher.writeRaw(SSH_FXP_INIT, initPayload.array())

            // Read SSH_FXP_VERSION
            val versionPacket = dispatcher.readRaw()
            if (versionPacket.type != SSH_FXP_VERSION) {
                throw SftpProtocolException(
                    "Expected SSH_FXP_VERSION (2), got ${versionPacket.type}"
                )
            }
            if (versionPacket.payload.size < 4) {
                throw SftpProtocolException("SSH_FXP_VERSION payload too short")
            }
            val serverVersion = ByteBuffer.wrap(versionPacket.payload, 0, 4).int
            val negotiatedVersion = minOf(SFTP_VERSION, serverVersion)
            logger.info("SFTP version negotiated: {} (server: {})", negotiatedVersion, serverVersion)

            // Start the background read loop
            val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            val readJob = dispatcher.startReadLoop(scope)

            return SftpClientImpl(session, dispatcher, readJob, negotiatedVersion)
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

        /** Decode a STATUS response into an SftpException. */
        private fun decodeStatusException(payload: ByteArray): SftpException {
            val buf = ByteBuffer.wrap(payload)
            val code = if (buf.remaining() >= 4) buf.int else 4
            val statusCode = SftpStatusCode.fromCode(code)
            val message = if (buf.remaining() >= 4) {
                val msgBytes = extractString(buf)
                String(msgBytes, StandardCharsets.UTF_8)
            } else {
                statusCode.name
            }
            return SftpException(statusCode, message)
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

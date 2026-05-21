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

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.SftpAttributes
import org.connectbot.sshlib.SftpClient
import org.connectbot.sshlib.SftpDirectoryEntry
import org.connectbot.sshlib.SftpFileHandle
import org.connectbot.sshlib.SftpOpenFlag
import org.connectbot.sshlib.SftpResult
import org.connectbot.sshlib.SftpStatusCode
import org.connectbot.sshlib.SshSession
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SftpClientImplTest {

    @Test
    fun `create negotiates version and close is idempotent`() = runBlocking {
        val session = FakeSshSession()
        session.enqueueRead(packet(SSH_FXP_VERSION, ByteBuffer.allocate(4).putInt(5).array()))
        val client = createClient(session)

        assertEquals(3, client.protocolVersion)
        assertTrue(client.isOpen)
        client.close()
        client.close()
        assertFalse(client.isOpen)
        assertEquals(1, session.closeCalls)
    }

    @Test
    fun `create returns protocol errors for malformed version response`() = runBlocking {
        val wrongTypeSession = FakeSshSession()
        wrongTypeSession.enqueueRead(packet(SSH_FXP_STATUS, statusPayload(SftpStatusCode.OK)))
        assertIs<SftpResult.ProtocolError>(SftpClientImpl.create(wrongTypeSession))

        val shortPayloadSession = FakeSshSession()
        shortPayloadSession.enqueueRead(packet(SSH_FXP_VERSION, byteArrayOf(0, 0, 0)))
        assertIs<SftpResult.ProtocolError>(SftpClientImpl.create(shortPayloadSession))
    }

    @Test
    fun `create propagates write and read errors`() = runBlocking {
        val writeFailureSession = FakeSshSession(writeFailure = IllegalStateException("cannot write"))
        assertIs<SftpResult.IoError>(SftpClientImpl.create(writeFailureSession))

        val readFailureSession = FakeSshSession()
        assertIs<SftpResult.IoError>(SftpClientImpl.create(readFailureSession))
    }

    @Test
    fun `create propagates protocol and server handshake results`() = runBlocking {
        assertIs<SftpResult.ProtocolError>(
            SftpClientImpl.create(
                FakeSshSession(),
                FakeHandshakeTransport(writeResult = SftpResult.ProtocolError("init rejected")),
            ),
        )
        assertIs<SftpResult.ServerError>(
            SftpClientImpl.create(
                FakeSshSession(),
                FakeHandshakeTransport(writeResult = SftpResult.ServerError(SftpStatusCode.FAILURE, "init failed")),
            ),
        )
        assertIs<SftpResult.ProtocolError>(
            SftpClientImpl.create(
                FakeSshSession(),
                FakeHandshakeTransport(readResult = SftpResult.ProtocolError("bad version")),
            ),
        )
        assertIs<SftpResult.ServerError>(
            SftpClientImpl.create(
                FakeSshSession(),
                FakeHandshakeTransport(readResult = SftpResult.ServerError(SftpStatusCode.FAILURE, "version failed")),
            ),
        )
    }

    @Test
    fun `file operations map successful responses`() = runBlocking {
        val session = FakeSshSession(
            responseFor = { type, _ ->
                when (type) {
                    SSH_FXP_OPEN -> response(SSH_FXP_HANDLE, stringPayload(byteArrayOf(1, 2, 3)))
                    SSH_FXP_READ -> response(SSH_FXP_DATA, stringPayload(byteArrayOf(4, 5, 6)))
                    SSH_FXP_WRITE, SSH_FXP_CLOSE -> response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.OK))
                    else -> error("unexpected request $type")
                }
            },
        )
        val client = createClient(session)

        val handle = assertSuccess(client.open("/tmp/file", setOf(SftpOpenFlag.READ, SftpOpenFlag.WRITE)))
        assertContentEquals(byteArrayOf(1, 2, 3), handle.handle)
        assertContentEquals(byteArrayOf(4, 5, 6), assertSuccess(client.read(handle, 7, 3))!!)
        assertEquals(SftpResult.Success(Unit), client.write(handle, 8, byteArrayOf(9)))
        assertEquals(SftpResult.Success(Unit), client.close(handle))

        assertEquals(listOf(SSH_FXP_OPEN, SSH_FXP_READ, SSH_FXP_WRITE, SSH_FXP_CLOSE), session.requestTypes)
    }

    @Test
    fun `file operations map eof status errors and unexpected packets`() = runBlocking {
        val handle = SftpFileHandle(byteArrayOf(1))
        val eofClient = createClient(
            FakeSshSession(responseFor = { type, _ ->
                when (type) {
                    SSH_FXP_READ -> response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.EOF))
                    SSH_FXP_CLOSE -> response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.PERMISSION_DENIED, "denied"))
                    else -> response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.NO_SUCH_FILE, "missing"))
                }
            }),
        )

        val readErrorClient = createClient(
            FakeSshSession(responseFor = { _, _ -> response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.FAILURE, "failed")) }),
        )
        assertIs<SftpResult.ServerError>(readErrorClient.read(handle, 0, 1))

        assertEquals(SftpResult.Success(null), eofClient.read(handle, 0, 1))
        val closeError = assertIs<SftpResult.ServerError>(eofClient.close(handle))
        assertEquals(SftpStatusCode.PERMISSION_DENIED, closeError.statusCode)
        assertEquals("denied", closeError.message)
        assertIs<SftpResult.ServerError>(eofClient.open("/missing", setOf(SftpOpenFlag.READ)))

        val protocolClient = createClient(
            FakeSshSession(responseFor = { _, _ -> response(SSH_FXP_VERSION, byteArrayOf()) }),
        )
        assertIs<SftpResult.ProtocolError>(protocolClient.open("/bad", setOf(SftpOpenFlag.READ)))
        assertIs<SftpResult.ProtocolError>(protocolClient.read(handle, 0, 1))
        assertEquals(SftpResult.Success(Unit), protocolClient.close(handle))
    }

    @Test
    fun `stat and mutation operations map responses`() = runBlocking {
        val attrs = SftpAttributes(size = 42, permissions = 0b110_100_100)
        val session = FakeSshSession(
            responseFor = { type, _ ->
                when (type) {
                    SSH_FXP_STAT, SSH_FXP_LSTAT, SSH_FXP_FSTAT -> response(SSH_FXP_ATTRS, SftpFileAttributes.encode(attrs))

                    SSH_FXP_SETSTAT, SSH_FXP_FSETSTAT, SSH_FXP_MKDIR, SSH_FXP_RMDIR,
                    SSH_FXP_REMOVE, SSH_FXP_RENAME, SSH_FXP_SYMLINK,
                    -> response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.OK))

                    else -> error("unexpected request $type")
                }
            },
        )
        val client = createClient(session)
        val handle = SftpFileHandle(byteArrayOf(1))

        assertEquals(attrs, assertSuccess(client.stat("/path")))
        assertEquals(attrs, assertSuccess(client.lstat("/path")))
        assertEquals(attrs, assertSuccess(client.fstat(handle)))
        assertEquals(SftpResult.Success(Unit), client.setstat("/path", attrs))
        assertEquals(SftpResult.Success(Unit), client.fsetstat(handle, attrs))
        assertEquals(SftpResult.Success(Unit), client.mkdir("/dir", attrs))
        assertEquals(SftpResult.Success(Unit), client.rmdir("/dir"))
        assertEquals(SftpResult.Success(Unit), client.remove("/file"))
        assertEquals(SftpResult.Success(Unit), client.rename("/old", "/new"))
        assertEquals(SftpResult.Success(Unit), client.symlink("/target", "/link"))
    }

    @Test
    fun `stat and status operations map errors and unexpected success packets`() = runBlocking {
        val errorClient = createClient(
            FakeSshSession(responseFor = { _, _ -> response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.FAILURE)) }),
        )
        val handle = SftpFileHandle(byteArrayOf(1))

        assertIs<SftpResult.ServerError>(errorClient.stat("/path"))
        assertIs<SftpResult.ServerError>(errorClient.fstat(handle))
        assertIs<SftpResult.ServerError>(errorClient.remove("/path"))

        val protocolClient = createClient(FakeSshSession(responseFor = { _, _ -> response(SSH_FXP_VERSION, byteArrayOf()) }))
        assertIs<SftpResult.ProtocolError>(protocolClient.stat("/path"))
        assertIs<SftpResult.ProtocolError>(protocolClient.fstat(handle))
        assertEquals(SftpResult.Success(Unit), protocolClient.remove("/path"))
    }

    @Test
    fun `directory and path operations map name responses`() = runBlocking {
        val entries = listOf(
            SftpDirectoryEntry("alpha", "long alpha", SftpAttributes(size = 1)),
            SftpDirectoryEntry("beta", "long beta", SftpAttributes(size = 2)),
        )
        val session = FakeSshSession(
            responseFor = { type, _ ->
                when (type) {
                    SSH_FXP_OPENDIR -> response(SSH_FXP_HANDLE, stringPayload(byteArrayOf(9)))
                    SSH_FXP_READDIR -> response(SSH_FXP_NAME, namePayload(entries))
                    SSH_FXP_REALPATH -> response(SSH_FXP_NAME, namePayload(listOf(entries[0])))
                    SSH_FXP_READLINK -> response(SSH_FXP_NAME, namePayload(listOf(entries[1])))
                    else -> error("unexpected request $type")
                }
            },
        )
        val client = createClient(session)
        val handle = assertSuccess(client.opendir("/dir"))

        assertContentEquals(byteArrayOf(9), handle.handle)
        assertEquals(entries, assertSuccess(client.readdir(handle)))
        assertEquals("alpha", assertSuccess(client.realpath(".")))
        assertEquals("beta", assertSuccess(client.readlink("/link")))
    }

    @Test
    fun `directory and path operations map eof empty names and protocol errors`() = runBlocking {
        val handle = SftpFileHandle(byteArrayOf(1))
        val eofClient = createClient(
            FakeSshSession(responseFor = { _, _ -> response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.EOF)) }),
        )
        assertEquals(SftpResult.Success(null), eofClient.readdir(handle))

        val errorClient = createClient(
            FakeSshSession(responseFor = { _, _ -> response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.FAILURE, "failed")) }),
        )
        assertIs<SftpResult.ServerError>(errorClient.opendir("/dir"))
        assertIs<SftpResult.ServerError>(errorClient.readdir(handle))
        assertIs<SftpResult.ServerError>(errorClient.realpath("."))
        assertIs<SftpResult.ServerError>(errorClient.readlink("/link"))

        val emptyNameClient = createClient(
            FakeSshSession(responseFor = { _, _ -> response(SSH_FXP_NAME, namePayload(emptyList())) }),
        )
        assertIs<SftpResult.ProtocolError>(emptyNameClient.realpath("."))
        assertIs<SftpResult.ProtocolError>(emptyNameClient.readlink("/link"))

        val protocolClient = createClient(FakeSshSession(responseFor = { _, _ -> response(SSH_FXP_VERSION, byteArrayOf()) }))
        assertIs<SftpResult.ProtocolError>(protocolClient.opendir("/dir"))
        assertIs<SftpResult.ProtocolError>(protocolClient.readdir(handle))
        assertIs<SftpResult.ProtocolError>(protocolClient.realpath("."))
        assertIs<SftpResult.ProtocolError>(protocolClient.readlink("/link"))
    }

    @Test
    fun `dispatcher propagates request write failures`() = runBlocking {
        val client = createClient(FakeSshSession(failAfterHandshake = IllegalStateException("write failed")))

        val result = client.remove("/file")

        assertIs<SftpResult.IoError>(result)
    }

    private suspend fun createClient(session: FakeSshSession): SftpClient {
        session.enqueueRead(packet(SSH_FXP_VERSION, ByteBuffer.allocate(4).putInt(3).array()))
        return assertSuccess(SftpClientImpl.create(session))
    }

    private fun response(type: Int, payload: ByteArray): SftpRawPacket = SftpRawPacket(type, payload)

    private fun packet(type: Int, payload: ByteArray): ByteArray {
        val packet = ByteBuffer.allocate(4 + 1 + payload.size)
        packet.putInt(1 + payload.size)
        packet.put(type.toByte())
        packet.put(payload)
        return packet.array()
    }

    private fun responsePacket(type: Int, requestId: Int, payload: ByteArray): ByteArray {
        val responsePayload = ByteBuffer.allocate(4 + payload.size)
        responsePayload.putInt(requestId)
        responsePayload.put(payload)
        return packet(type, responsePayload.array())
    }

    private fun stringPayload(data: ByteArray): ByteArray {
        val payload = ByteBuffer.allocate(4 + data.size)
        payload.putInt(data.size)
        payload.put(data)
        return payload.array()
    }

    private fun statusPayload(code: SftpStatusCode, message: String = code.name): ByteArray {
        val msg = message.toByteArray(Charsets.UTF_8)
        val lang = ByteArray(0)
        val payload = ByteBuffer.allocate(4 + 4 + msg.size + 4 + lang.size)
        payload.putInt(code.code)
        payload.putInt(msg.size)
        payload.put(msg)
        payload.putInt(lang.size)
        payload.put(lang)
        return payload.array()
    }

    private fun namePayload(entries: List<SftpDirectoryEntry>): ByteArray {
        val encodedEntries = entries.map { entry ->
            val filename = entry.filename.toByteArray(Charsets.UTF_8)
            val longname = entry.longname.toByteArray(Charsets.UTF_8)
            val attrs = SftpFileAttributes.encode(entry.attrs)
            ByteBuffer.allocate(4 + filename.size + 4 + longname.size + attrs.size).apply {
                putInt(filename.size)
                put(filename)
                putInt(longname.size)
                put(longname)
                put(attrs)
            }.array()
        }
        val payload = ByteBuffer.allocate(4 + encodedEntries.sumOf { it.size })
        payload.putInt(entries.size)
        encodedEntries.forEach(payload::put)
        return payload.array()
    }

    private fun <T> assertSuccess(result: SftpResult<T>): T {
        assertIs<SftpResult.Success<T>>(result)
        return result.value
    }

    private inner class FakeSshSession(
        private val responseFor: (type: Int, payload: ByteArray) -> SftpRawPacket = { _, _ ->
            response(SSH_FXP_STATUS, statusPayload(SftpStatusCode.OK))
        },
        private val writeFailure: Throwable? = null,
        private val failAfterHandshake: Throwable? = null,
    ) : SshSession {
        private val reads = Channel<ByteArray>(Channel.UNLIMITED)
        private var writes = 0
        private var open = true
        val requestTypes = mutableListOf<Int>()
        var closeCalls = 0

        override val localChannelNumber: Int = 1
        override val remoteChannelNumber: Int = 2
        override val isOpen: Boolean get() = open
        override val stdout: ReceiveChannel<ByteArray> = Channel()
        override val stderr: ReceiveChannel<ByteArray> = Channel()

        fun enqueueRead(data: ByteArray) {
            reads.trySend(data).getOrThrow()
        }

        override suspend fun requestPty(
            terminalType: String,
            widthChars: Int,
            heightRows: Int,
            widthPixels: Int,
            heightPixels: Int,
            terminalModes: ByteArray,
        ): Boolean = true

        override suspend fun resizeTerminal(
            widthChars: Int,
            heightRows: Int,
            widthPixels: Int,
            heightPixels: Int,
        ): Boolean = true

        override suspend fun requestShell(): Boolean = true

        override suspend fun requestExec(command: String): Boolean = true

        override suspend fun requestSubsystem(name: String): Boolean = true

        override suspend fun write(data: ByteArray) {
            writeFailure?.let { throw it }
            writes++
            if (writes == 1) return
            failAfterHandshake?.let { throw it }

            val body = ByteBuffer.wrap(data)
            val length = body.int
            val type = body.get().toInt() and 0xFF
            val payload = ByteArray(length - 1)
            body.get(payload)
            val requestId = ByteBuffer.wrap(payload, 0, 4).int
            val requestPayload = payload.copyOfRange(4, payload.size)
            requestTypes += type
            val response = responseFor(type, requestPayload)
            enqueueRead(responsePacket(response.type, requestId, response.payload))
        }

        override suspend fun read(): ByteArray? = reads.receiveCatching().getOrNull()

        override suspend fun readExtended(): Pair<Int, ByteArray>? = null

        override suspend fun sendEof() = Unit

        override fun close() {
            closeCalls++
            open = false
            reads.close()
        }
    }

    private class FakeHandshakeTransport(
        private val writeResult: SftpResult<Unit> = SftpResult.Success(Unit),
        private val readResult: SftpResult<SftpRawPacket> = SftpResult.Success(
            SftpRawPacket(SSH_FXP_VERSION, ByteBuffer.allocate(4).putInt(3).array()),
        ),
    ) : SftpPacketTransport {
        override suspend fun readPacket(): SftpResult<SftpRawPacket> = readResult

        override suspend fun writePacket(type: Int, payload: ByteArray): SftpResult<Unit> = writeResult
    }

    private companion object {
        const val SSH_FXP_VERSION = 2
        const val SSH_FXP_OPEN = 3
        const val SSH_FXP_CLOSE = 4
        const val SSH_FXP_READ = 5
        const val SSH_FXP_WRITE = 6
        const val SSH_FXP_LSTAT = 7
        const val SSH_FXP_FSTAT = 8
        const val SSH_FXP_SETSTAT = 9
        const val SSH_FXP_FSETSTAT = 10
        const val SSH_FXP_OPENDIR = 11
        const val SSH_FXP_READDIR = 12
        const val SSH_FXP_REMOVE = 13
        const val SSH_FXP_MKDIR = 14
        const val SSH_FXP_RMDIR = 15
        const val SSH_FXP_REALPATH = 16
        const val SSH_FXP_STAT = 17
        const val SSH_FXP_RENAME = 18
        const val SSH_FXP_READLINK = 19
        const val SSH_FXP_SYMLINK = 20
        const val SSH_FXP_STATUS = 101
        const val SSH_FXP_HANDLE = 102
        const val SSH_FXP_DATA = 103
        const val SSH_FXP_NAME = 104
        const val SSH_FXP_ATTRS = 105
    }
}

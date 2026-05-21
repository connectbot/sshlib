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

package org.connectbot.sshlib

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SftpClientTest {

    @Test
    fun `listdir accumulates batches and closes directory handle`() = runBlocking {
        val first = SftpDirectoryEntry("one", "one", SftpAttributes(size = 1))
        val second = SftpDirectoryEntry("two", "two", SftpAttributes(size = 2))
        val client = FakeSftpClient(
            readResults = ArrayDeque(
                listOf(
                    SftpResult.Success(listOf(first)),
                    SftpResult.Success(listOf(second)),
                    SftpResult.Success(null),
                ),
            ),
        )

        val result = client.listdir("/tmp")

        assertEquals(SftpResult.Success(listOf(first, second)), result)
        assertEquals(listOf("/tmp"), client.openedPaths)
        assertEquals(listOf(client.handle), client.closedHandles)
    }

    @Test
    fun `listdir returns opendir server errors without closing unopened handle`() = runBlocking {
        val error = SftpResult.ServerError(SftpStatusCode.NO_SUCH_FILE, "missing")
        val client = FakeSftpClient(openResult = error)

        assertEquals(error, client.listdir("/missing"))
        assertTrue(client.closedHandles.isEmpty())
    }

    @Test
    fun `listdir returns opendir protocol errors`() = runBlocking {
        val error = SftpResult.ProtocolError("bad handle")
        val client = FakeSftpClient(openResult = error)

        assertEquals(error, client.listdir("/bad"))
        assertTrue(client.closedHandles.isEmpty())
    }

    @Test
    fun `listdir returns opendir io errors`() = runBlocking {
        val error = SftpResult.IoError(IllegalStateException("closed"))
        val client = FakeSftpClient(openResult = error)

        assertEquals(error, client.listdir("/io"))
        assertTrue(client.closedHandles.isEmpty())
    }

    @Test
    fun `listdir returns readdir server errors and closes handle`() = runBlocking {
        val error = SftpResult.ServerError(SftpStatusCode.PERMISSION_DENIED, "denied")
        val client = FakeSftpClient(readResults = ArrayDeque(listOf(error)))

        assertEquals(error, client.listdir("/denied"))
        assertEquals(listOf(client.handle), client.closedHandles)
    }

    @Test
    fun `listdir returns readdir protocol errors and closes handle`() = runBlocking {
        val error = SftpResult.ProtocolError("unexpected packet")
        val client = FakeSftpClient(readResults = ArrayDeque(listOf(error)))

        assertEquals(error, client.listdir("/protocol"))
        assertEquals(listOf(client.handle), client.closedHandles)
    }

    @Test
    fun `listdir returns readdir io errors and closes handle`() = runBlocking {
        val error = SftpResult.IoError(IllegalStateException("read failed"))
        val client = FakeSftpClient(readResults = ArrayDeque(listOf(error)))

        assertEquals(error, client.listdir("/io"))
        assertEquals(listOf(client.handle), client.closedHandles)
    }

    private class FakeSftpClient(
        private val openResult: SftpResult<SftpFileHandle> = SftpResult.Success(SftpFileHandle(byteArrayOf(1, 2, 3))),
        private val readResults: ArrayDeque<SftpResult<List<SftpDirectoryEntry>?>> = ArrayDeque(),
    ) : SftpClient {
        val handle = (openResult as? SftpResult.Success)?.value ?: SftpFileHandle(byteArrayOf(9))
        val openedPaths = mutableListOf<String>()
        val closedHandles = mutableListOf<SftpFileHandle>()

        override val protocolVersion: Int = 3
        override val isOpen: Boolean = true

        override suspend fun open(
            path: String,
            flags: Set<SftpOpenFlag>,
            attrs: SftpAttributes,
        ): SftpResult<SftpFileHandle> = throw UnsupportedOperationException()

        override suspend fun close(handle: SftpFileHandle): SftpResult<Unit> {
            closedHandles += handle
            return SftpResult.Success(Unit)
        }

        override suspend fun read(handle: SftpFileHandle, offset: Long, length: Int): SftpResult<ByteArray?> = throw UnsupportedOperationException()

        override suspend fun write(handle: SftpFileHandle, offset: Long, data: ByteArray): SftpResult<Unit> = throw UnsupportedOperationException()

        override suspend fun stat(path: String): SftpResult<SftpAttributes> = throw UnsupportedOperationException()

        override suspend fun lstat(path: String): SftpResult<SftpAttributes> = throw UnsupportedOperationException()

        override suspend fun fstat(handle: SftpFileHandle): SftpResult<SftpAttributes> = throw UnsupportedOperationException()

        override suspend fun setstat(path: String, attrs: SftpAttributes): SftpResult<Unit> = throw UnsupportedOperationException()

        override suspend fun fsetstat(handle: SftpFileHandle, attrs: SftpAttributes): SftpResult<Unit> = throw UnsupportedOperationException()

        override suspend fun opendir(path: String): SftpResult<SftpFileHandle> {
            openedPaths += path
            return openResult
        }

        override suspend fun readdir(handle: SftpFileHandle): SftpResult<List<SftpDirectoryEntry>?> = readResults.removeFirst()

        override suspend fun mkdir(path: String, attrs: SftpAttributes): SftpResult<Unit> = throw UnsupportedOperationException()

        override suspend fun rmdir(path: String): SftpResult<Unit> = throw UnsupportedOperationException()

        override suspend fun remove(path: String): SftpResult<Unit> = throw UnsupportedOperationException()

        override suspend fun rename(oldPath: String, newPath: String): SftpResult<Unit> = throw UnsupportedOperationException()

        override suspend fun realpath(path: String): SftpResult<String> = throw UnsupportedOperationException()

        override suspend fun readlink(path: String): SftpResult<String> = throw UnsupportedOperationException()

        override suspend fun symlink(targetPath: String, linkPath: String): SftpResult<Unit> = throw UnsupportedOperationException()

        override fun close() = Unit
    }
}

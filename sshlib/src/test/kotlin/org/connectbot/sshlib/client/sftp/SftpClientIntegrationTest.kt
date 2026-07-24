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

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SftpClient
import org.connectbot.sshlib.SftpOpenFlag
import org.connectbot.sshlib.SftpResult
import org.connectbot.sshlib.SftpStatusCode
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.getOrThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.images.builder.ImageFromDockerfile
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers

/**
 * Integration tests for SFTP client against a real OpenSSH server.
 */
@Testcontainers
class SftpClientIntegrationTest {

    companion object {
        private val logger = LoggerFactory.getLogger(SftpClientIntegrationTest::class.java)
        private val logConsumer = Slf4jLogConsumer(logger).withPrefix("DOCKER")

        private const val USERNAME = "testuser"
        private const val PASSWORD = "testpass"

        // Tarball-name format expected by wget in the test Dockerfile
        // (`openssh-${OPENSSH_VERSION}.tar.gz`). The renovate annotation
        // there extracts this from the github tag `V_9_9_P2`.
        private const val OPENSSH_VERSION = "9.9p2"
        private const val DEBUG_CFLAGS = ""

        @Container
        @JvmStatic
        val opensshContainer: GenericContainer<*> = GenericContainer(
            ImageFromDockerfile("openssh-sftp-test", false)
                .withFileFromClasspath(".", "openssh-server")
                .withFileFromClasspath("test_rsa.pub", "keys/rsa_unencrypted.pub")
                .withBuildArg("OPENSSH_VERSION", OPENSSH_VERSION)
                .withBuildArg("DEBUG_CFLAGS", DEBUG_CFLAGS),
        )
            .withExposedPorts(22)
            .withLogConsumer(logConsumer)
            .waitingFor(
                Wait.forLogMessage(".*Server listening.*", 1),
            )
    }

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private suspend fun openSftp(
        rekeyIntervalMs: Long = 3_600_000L,
        rekeyBytesLimit: Long = 1_073_741_824L,
    ): Pair<SshClient, SftpClient> {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
            this.rekeyIntervalMs = rekeyIntervalMs
            this.rekeyBytesLimit = rekeyBytesLimit
        }
        val client = SshClient(config)

        val connectResult = client.connect()
        assertTrue(connectResult is org.connectbot.sshlib.ConnectResult.Success, "Should connect to SSH server, got: $connectResult")
        val authResult = client.authenticatePassword(USERNAME, PASSWORD)
        assertTrue(authResult is org.connectbot.sshlib.AuthResult.Success, "Should authenticate, got: $authResult")

        val sftpResult = client.openSftp()
        assertTrue(sftpResult is SftpResult.Success, "Should open SFTP session, got: $sftpResult")
        val sftp = (sftpResult as SftpResult.Success).value
        return Pair(client, sftp)
    }

    @Test
    fun `should negotiate SFTP version 3`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            assertTrue(sftp.protocolVersion >= 3, "SFTP version should be >= 3")
            assertTrue(sftp.isOpen, "SFTP session should be open")
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should stat root directory`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val attrs = sftp.stat("/").getOrThrow()
            assertNotNull(attrs.permissions, "Root dir should have permissions")
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should resolve realpath`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val path = sftp.realpath(".").getOrThrow()
            assertTrue(path.startsWith("/"), "Realpath should return absolute path: $path")
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should create write read and delete file`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val testPath = "/tmp/sftp-test-${System.currentTimeMillis()}.txt"
            val testData = "Hello SFTP!\n".toByteArray()

            // Create and write
            val handle = sftp.open(
                testPath,
                setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE, SftpOpenFlag.TRUNCATE),
            ).getOrThrow()
            sftp.write(handle, 0, testData).getOrThrow()
            sftp.close(handle).getOrThrow()

            // Read back
            val readHandle = sftp.open(testPath, setOf(SftpOpenFlag.READ)).getOrThrow()
            val readData = sftp.read(readHandle, 0, testData.size).getOrThrow()
            sftp.close(readHandle).getOrThrow()

            assertNotNull(readData)
            assertTrue(testData.contentEquals(readData!!), "Read data should match written data")

            // Stat
            val attrs = sftp.stat(testPath).getOrThrow()
            assertEquals(testData.size.toLong(), attrs.size, "File size should match")

            // Delete
            sftp.remove(testPath).getOrThrow()

            // Verify deleted
            val result = sftp.stat(testPath)
            assertTrue(result is SftpResult.ServerError, "stat should fail after delete")
            assertEquals(SftpStatusCode.NO_SUCH_FILE, (result as SftpResult.ServerError).statusCode)
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should list directory`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val entries = sftp.listdir("/tmp").getOrThrow()
            assertTrue(entries.isNotEmpty(), "Directory listing should not be empty")
            assertTrue(entries.any { it.filename == "." }, "Should contain '.'")
            assertTrue(entries.any { it.filename == ".." }, "Should contain '..'")
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should create and remove directory`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val dirPath = "/tmp/sftp-dir-${System.currentTimeMillis()}"

            sftp.mkdir(dirPath).getOrThrow()

            val attrs = sftp.stat(dirPath).getOrThrow()
            assertNotNull(attrs.permissions)

            sftp.rmdir(dirPath).getOrThrow()

            val result = sftp.stat(dirPath)
            assertTrue(result is SftpResult.ServerError, "stat should fail after rmdir")
            assertEquals(SftpStatusCode.NO_SUCH_FILE, (result as SftpResult.ServerError).statusCode)
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should rename a file`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val ts = System.currentTimeMillis()
            val oldPath = "/tmp/sftp-old-$ts.txt"
            val newPath = "/tmp/sftp-new-$ts.txt"

            // Create file
            val handle = sftp.open(oldPath, setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE)).getOrThrow()
            sftp.write(handle, 0, "rename test".toByteArray()).getOrThrow()
            sftp.close(handle).getOrThrow()

            // Rename
            sftp.rename(oldPath, newPath).getOrThrow()

            // Old path should not exist
            val result = sftp.stat(oldPath)
            assertTrue(result is SftpResult.ServerError, "Old path should not exist after rename")
            assertEquals(SftpStatusCode.NO_SUCH_FILE, (result as SftpResult.ServerError).statusCode)

            // New path should exist
            sftp.stat(newPath).getOrThrow()

            // Cleanup
            sftp.remove(newPath).getOrThrow()
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should handle file not found`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val result = sftp.stat("/nonexistent/path/that/does/not/exist")
            assertTrue(result is SftpResult.ServerError, "Should return ServerError for nonexistent path")
            assertEquals(SftpStatusCode.NO_SUCH_FILE, (result as SftpResult.ServerError).statusCode)
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should handle large file transfer`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val testPath = "/tmp/sftp-large-${System.currentTimeMillis()}.bin"
            // 64KB — exercises SSH channel window adjustment
            val testData = ByteArray(64 * 1024) { (it % 256).toByte() }

            val writeHandle = sftp.open(
                testPath,
                setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE, SftpOpenFlag.TRUNCATE),
            ).getOrThrow()
            sftp.write(writeHandle, 0, testData).getOrThrow()
            sftp.close(writeHandle).getOrThrow()

            // Read back in chunks
            val readHandle = sftp.open(testPath, setOf(SftpOpenFlag.READ)).getOrThrow()
            val readBuffer = mutableListOf<Byte>()
            var offset = 0L
            while (true) {
                val chunk = sftp.read(readHandle, offset, 16384).getOrThrow() ?: break
                readBuffer.addAll(chunk.toList())
                offset += chunk.size
            }
            sftp.close(readHandle).getOrThrow()

            assertEquals(testData.size, readBuffer.size, "Should read back all bytes")
            assertTrue(
                testData.contentEquals(readBuffer.toByteArray()),
                "Read data should match written data",
            )

            sftp.remove(testPath).getOrThrow()
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `SFTP write continues across byte limit rekey`() = runBlocking {
        val (client, sftp) = openSftp(
            rekeyIntervalMs = Long.MAX_VALUE,
            rekeyBytesLimit = 256L * 1024,
        )
        val remoteDirectory = sftp.realpath(".").getOrThrow().trimEnd('/')
        val testPath = "$remoteDirectory/sftp-rekey-write-${System.currentTimeMillis()}.bin"
        try {
            withTimeout(30_000) {
                val handle = sftp.open(
                    testPath,
                    setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE, SftpOpenFlag.TRUNCATE),
                ).getOrThrow()
                val chunk = ByteArray(32 * 1024) { (it % 251).toByte() }
                repeat(64) { index ->
                    sftp.write(handle, index.toLong() * chunk.size, chunk).getOrThrow()
                }
                sftp.close(handle).getOrThrow()

                val attrs = sftp.stat(testPath).getOrThrow()
                assertEquals(2L * 1024 * 1024, attrs.size, "All data should be written across rekey")
            }
        } finally {
            sftp.remove(testPath)
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should advertise the copy-data extension`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            // OpenSSH added "copy-data" in 9.0; the test container runs 9.9p2, so a real
            // server should always advertise it here. This is the strongest signal that
            // VERSION extension-pair parsing (SftpClientImpl.create) works against real
            // wire bytes, not just the hand-built payloads in SftpClientImplTest.
            assertTrue(
                "copy-data" in sftp.extensions,
                "Expected OpenSSH 9.9p2 to advertise the copy-data extension, got: ${sftp.extensions}",
            )
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `SFTP operation completes after interval rekey while idle`() = runBlocking {
        val (client, sftp) = openSftp(
            rekeyIntervalMs = 1_000L,
            rekeyBytesLimit = Long.MAX_VALUE,
        )
        try {
            val remoteDirectory = sftp.realpath(".").getOrThrow()
            delay(2_500L)
            withTimeout(10_000L) {
                val handle = sftp.opendir(remoteDirectory).getOrThrow()
                sftp.close(handle).getOrThrow()
            }
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `copyData copies bytes entirely on the server`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val ts = System.currentTimeMillis()
            val srcPath = "/tmp/sftp-copydata-src-$ts.bin"
            val dstPath = "/tmp/sftp-copydata-dst-$ts.bin"
            val testData = ByteArray(8192) { (it % 256).toByte() }

            val writeHandle = sftp.open(
                srcPath,
                setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE, SftpOpenFlag.TRUNCATE),
            ).getOrThrow()
            sftp.write(writeHandle, 0, testData).getOrThrow()
            sftp.close(writeHandle).getOrThrow()

            val srcHandle = sftp.open(srcPath, setOf(SftpOpenFlag.READ)).getOrThrow()
            val dstHandle = sftp.open(
                dstPath,
                setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE, SftpOpenFlag.TRUNCATE),
            ).getOrThrow()

            // length=0 means "copy through EOF of the source file" per the extension spec.
            sftp.copyData(srcHandle, 0L, 0L, dstHandle, 0L).getOrThrow()

            sftp.close(srcHandle).getOrThrow()
            sftp.close(dstHandle).getOrThrow()

            val dstAttrs = sftp.stat(dstPath).getOrThrow()
            assertEquals(testData.size.toLong(), dstAttrs.size, "Copied file size should match source")

            val readHandle = sftp.open(dstPath, setOf(SftpOpenFlag.READ)).getOrThrow()
            val readData = sftp.read(readHandle, 0, testData.size).getOrThrow()
            sftp.close(readHandle).getOrThrow()

            assertNotNull(readData)
            assertTrue(testData.contentEquals(readData!!), "Server-side copied bytes should match the source")

            sftp.remove(srcPath).getOrThrow()
            sftp.remove(dstPath).getOrThrow()
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should set file attributes`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val testPath = "/tmp/sftp-attrs-${System.currentTimeMillis()}.txt"

            val handle = sftp.open(testPath, setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE)).getOrThrow()
            sftp.close(handle).getOrThrow()

            // Set permissions to 0644
            sftp.setstat(testPath, org.connectbot.sshlib.SftpAttributes(permissions = 0b110_100_100)).getOrThrow()

            val attrs = sftp.stat(testPath).getOrThrow()
            assertEquals(
                0b110_100_100,
                (attrs.permissions ?: 0) and 0x1FF,
                "Permissions should be 0644",
            )

            sftp.remove(testPath).getOrThrow()
        } finally {
            sftp.close()
            client.disconnect()
        }
    }
}

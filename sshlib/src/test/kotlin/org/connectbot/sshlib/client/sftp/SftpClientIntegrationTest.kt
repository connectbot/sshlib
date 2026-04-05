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

import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SftpAttributes
import org.connectbot.sshlib.SftpClient
import org.connectbot.sshlib.SftpException
import org.connectbot.sshlib.SftpOpenFlag
import org.connectbot.sshlib.SftpStatusCode
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
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
        private const val OPENSSH_VERSION = "V_9_9_P2"
        private const val DEBUG_CFLAGS = ""

        @Container
        @JvmStatic
        val opensshContainer: GenericContainer<*> = GenericContainer(
            ImageFromDockerfile("openssh-sftp-test", false)
                .withFileFromClasspath(".", "openssh-server")
                .withBuildArg("OPENSSH_VERSION", OPENSSH_VERSION)
                .withBuildArg("DEBUG_CFLAGS", DEBUG_CFLAGS)
        )
            .withExposedPorts(22)
            .withLogConsumer(logConsumer)
            .waitingFor(
                Wait.forLogMessage(".*Server listening.*", 1)
            )
    }

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private suspend fun openSftp(): Pair<SshClient, SftpClient> {
        val host = opensshContainer.host
        val port = opensshContainer.getMappedPort(22)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            this.hostKeyVerifier = acceptAllVerifier
        }
        val client = SshClient(config)

        assertTrue(client.connect(), "Should connect to SSH server")
        assertTrue(client.authenticatePassword(USERNAME, PASSWORD), "Should authenticate")

        val sftp = client.openSftp()
        assertNotNull(sftp, "Should open SFTP session")
        return Pair(client, sftp!!)
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
            val attrs = sftp.stat("/")
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
            val path = sftp.realpath(".")
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
                setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE, SftpOpenFlag.TRUNCATE)
            )
            sftp.write(handle, 0, testData)
            sftp.close(handle)

            // Read back
            val readHandle = sftp.open(testPath, setOf(SftpOpenFlag.READ))
            val readData = sftp.read(readHandle, 0, testData.size)
            sftp.close(readHandle)

            assertNotNull(readData)
            assertTrue(testData.contentEquals(readData!!), "Read data should match written data")

            // Stat
            val attrs = sftp.stat(testPath)
            assertEquals(testData.size.toLong(), attrs.size, "File size should match")

            // Delete
            sftp.remove(testPath)

            // Verify deleted
            try {
                sftp.stat(testPath)
                fail("stat should fail after delete")
            } catch (e: SftpException) {
                assertEquals(SftpStatusCode.NO_SUCH_FILE, e.statusCode)
            }
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should list directory`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            val entries = sftp.listdir("/tmp")
            assertTrue(entries.isNotEmpty(), "Directory listing should not be empty")
            // /tmp always has . and ..
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

            sftp.mkdir(dirPath)

            val attrs = sftp.stat(dirPath)
            assertNotNull(attrs.permissions)

            sftp.rmdir(dirPath)

            try {
                sftp.stat(dirPath)
                fail("stat should fail after rmdir")
            } catch (e: SftpException) {
                assertEquals(SftpStatusCode.NO_SUCH_FILE, e.statusCode)
            }
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
            val handle = sftp.open(oldPath, setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE))
            sftp.write(handle, 0, "rename test".toByteArray())
            sftp.close(handle)

            // Rename
            sftp.rename(oldPath, newPath)

            // Old path should not exist
            try {
                sftp.stat(oldPath)
                fail("Old path should not exist after rename")
            } catch (e: SftpException) {
                assertEquals(SftpStatusCode.NO_SUCH_FILE, e.statusCode)
            }

            // New path should exist
            sftp.stat(newPath)

            // Cleanup
            sftp.remove(newPath)
        } finally {
            sftp.close()
            client.disconnect()
        }
    }

    @Test
    fun `should handle file not found`() = runBlocking {
        val (client, sftp) = openSftp()
        try {
            try {
                sftp.stat("/nonexistent/path/that/does/not/exist")
                fail("Should throw SftpException for nonexistent path")
            } catch (e: SftpException) {
                assertEquals(SftpStatusCode.NO_SUCH_FILE, e.statusCode)
            }
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
                setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE, SftpOpenFlag.TRUNCATE)
            )
            sftp.write(writeHandle, 0, testData)
            sftp.close(writeHandle)

            // Read back in chunks
            val readHandle = sftp.open(testPath, setOf(SftpOpenFlag.READ))
            val readBuffer = mutableListOf<Byte>()
            var offset = 0L
            while (true) {
                val chunk = sftp.read(readHandle, offset, 16384) ?: break
                readBuffer.addAll(chunk.toList())
                offset += chunk.size
            }
            sftp.close(readHandle)

            assertEquals(testData.size, readBuffer.size, "Should read back all bytes")
            assertTrue(
                testData.contentEquals(readBuffer.toByteArray()),
                "Read data should match written data"
            )

            sftp.remove(testPath)
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

            val handle = sftp.open(testPath, setOf(SftpOpenFlag.WRITE, SftpOpenFlag.CREATE))
            sftp.close(handle)

            // Set permissions to 0644
            sftp.setstat(testPath, SftpAttributes(permissions = 0b110_100_100)) // 0644

            val attrs = sftp.stat(testPath)
            // Check lower 9 bits (rwx for user/group/other)
            assertEquals(
                0b110_100_100,
                (attrs.permissions ?: 0) and 0x1FF,
                "Permissions should be 0644"
            )

            sftp.remove(testPath)
        } finally {
            sftp.close()
            client.disconnect()
        }
    }
}

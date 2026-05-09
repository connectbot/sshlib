package org.connectbot.sshlib.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.protocol.SshMsgExtInfo
import org.connectbot.sshlib.transport.PipedTransport
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class ExtInfoNegotiationTest {

    private val acceptAllVerifier = object : HostKeyVerifier {
        override suspend fun verify(key: PublicKey): Boolean = true
    }

    private suspend fun connectInBackground(
        connection: SshConnection,
        backgroundScope: CoroutineScope,
        dispatcher: CoroutineDispatcher,
    ): ConnectResult {
        val result = CompletableDeferred<ConnectResult>()
        backgroundScope.launch(dispatcher) { result.complete(connection.connect()) }
        yield()
        return result.await()
    }

    private fun extensionNames(extInfo: SshMsgExtInfo): Set<String> = extInfo.extensions().map { it.extensionName().value() }.toSet()

    private fun extensionValues(extInfo: SshMsgExtInfo): Map<String, ByteArray> = extInfo.extensions().associate { it.extensionName().value() to it.extensionValue().data() }

    @Suppress("UNCHECKED_CAST")
    private fun serverSigAlgs(connection: SshConnection): Set<String>? {
        val field = SshConnection::class.java.getDeclaredField("serverSigAlgs")
        field.isAccessible = true
        return field.get(connection) as Set<String>?
    }

    private suspend fun awaitServerSigAlgs(connection: SshConnection, expected: Set<String>) {
        withTimeout(1000) {
            while (serverSigAlgs(connection) != expected) {
                yield()
            }
        }
    }

    @Test
    fun `client sends EXT_INFO when server advertises ext-info-s`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            val extInfo = withTimeoutOrNull(1000) { server.awaitExtInfo() }
            assertNotNull(extInfo, "Expected EXT_INFO from client")
            val names = extensionNames(extInfo!!)
            assertTrue("ext-info-in-auth@openssh.com" in names)
            assertEquals(setOf("ext-info-in-auth@openssh.com"), names)
            val values = extensionValues(extInfo)
            assertContentEquals("0".toByteArray(Charsets.US_ASCII), values["ext-info-in-auth@openssh.com"])
        } finally {
            connection.close()
        }
    }

    @Test
    fun `client does NOT send EXT_INFO when server does not advertise ext-info-s`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = false
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            val extInfo = withTimeoutOrNull(1000) { server.awaitExtInfo() }
            assertNull(extInfo, "Did NOT expect EXT_INFO from client when server doesn't advertise it")
        } finally {
            connection.close()
        }
    }

    @Test
    fun `client does NOT send EXT_INFO when server kex only contains ext-info-s as substring`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.kexAlgorithms = "curve25519-sha256,not-ext-info-s"
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            val extInfo = withTimeoutOrNull(1000) { server.awaitExtInfo() }
            assertNull(extInfo, "Did NOT expect EXT_INFO unless server advertises ext-info-s as an exact kex name")
        } finally {
            connection.close()
        }
    }

    @Test
    fun `client appends ext-info-c to custom kex algorithms`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            kexAlgorithms = "curve25519-sha256",
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            val extInfo = withTimeoutOrNull(1000) { server.awaitExtInfo() }
            assertNotNull(extInfo, "Expected EXT_INFO from client after appending ext-info-c")
        } finally {
            connection.close()
        }
    }

    // --- stripExtInfoC / appendExtInfoC boundary tests ---

    @Test
    fun `client strips ext-info-c from kexAlgorithms before re-advertising it`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            kexAlgorithms = "curve25519-sha256,ext-info-c",
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)
            val kexInit = withTimeout(1000) { server.awaitClientKexInit() }
            val kexAlgs = kexInit.kexAlgorithms().entries().data()
            // ext-info-c must appear exactly once (appended), not duplicated
            assertEquals(1, kexAlgs.count { it == "ext-info-c" }, "ext-info-c should appear exactly once, got: $kexAlgs")
        } finally {
            connection.close()
        }
    }

    @Test
    fun `client appends ext-info-c when not present in custom kex list`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            kexAlgorithms = "curve25519-sha256",
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)
            val kexInit = withTimeout(1000) { server.awaitClientKexInit() }
            val kexAlgs = kexInit.kexAlgorithms().entries().data()
            assertTrue("ext-info-c" in kexAlgs, "ext-info-c should be appended to kex list: $kexAlgs")
        } finally {
            connection.close()
        }
    }

    // --- sendClientExtInfo guard: not sent twice ---

    @Test
    fun `client sends EXT_INFO at most once even after rekey`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            // Consume the initial EXT_INFO
            val first = withTimeout(1000) { server.awaitExtInfo() }
            assertNotNull(first)

            // Trigger a server-initiated rekey; the client must NOT send EXT_INFO again
            server.initiateRekey()
            server.sendIgnore()
            withTimeout(1000) { server.rekeyCount.first { it >= 1 } }

            val second = withTimeoutOrNull(300) { server.awaitExtInfo() }
            assertNull(second, "Client must not send EXT_INFO again after rekey")
        } finally {
            connection.close()
        }
    }

    // --- processServerExtInfo: count guard (>= 2 rejects third message) ---

    @Test
    fun `client ignores third EXT_INFO from server`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        var authJob: kotlinx.coroutines.Job? = null
        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)
            assertTrue(connection.serverSupportsPing, "Initial EXT_INFO should set ping support")

            // Second EXT_INFO (during auth) — allowed, but must not clear ping
            authJob = backgroundScope.launch(dispatcher) {
                connection.authenticatePassword("user", "pass")
            }
            withTimeout(1000) { server.awaitUserauthRequest() }
            server.sendCustomExtInfo(mapOf("server-sig-algs" to "rsa-sha2-256".toByteArray(Charsets.US_ASCII)))
            awaitServerSigAlgs(connection, setOf("rsa-sha2-256"))

            // Third EXT_INFO — must be ignored; ping support and sig-algs must remain unchanged
            server.sendCustomExtInfo(mapOf("server-sig-algs" to "ssh-ed25519".toByteArray(Charsets.US_ASCII)))
            // Drain only currently scheduled packet handling. advanceUntilIdle would also
            // advance virtual time far enough to fire the connection's rekey timer.
            runCurrent()
            assertEquals(setOf("rsa-sha2-256"), serverSigAlgs(connection), "Third EXT_INFO must be ignored")
            assertTrue(connection.serverSupportsPing, "Ping support must survive ignored third EXT_INFO")
        } finally {
            authJob?.cancel()
            connection.close()
        }
    }

    // --- processServerExtInfo: initialExtInfo flag (== 0 check) ---

    @Test
    fun `second EXT_INFO does not clear initial-only fields like ping and hostbound`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        var authJob: kotlinx.coroutines.Job? = null
        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)
            assertTrue(connection.serverSupportsPing, "Ping should be set by initial EXT_INFO")

            authJob = backgroundScope.launch(dispatcher) {
                connection.authenticatePassword("user", "pass")
            }
            withTimeout(1000) { server.awaitUserauthRequest() }

            // Second EXT_INFO without ping — ping must remain true (initial-only)
            server.sendCustomExtInfo(mapOf("server-sig-algs" to "rsa-sha2-256".toByteArray(Charsets.US_ASCII)))
            awaitServerSigAlgs(connection, setOf("rsa-sha2-256"))
            assertTrue(connection.serverSupportsPing, "Ping support must not be cleared by second EXT_INFO")
        } finally {
            authJob?.cancel()
            connection.close()
        }
    }

    @Test
    fun `initial EXT_INFO with no ping extension leaves serverSupportsPing false`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = false // no ping in initial EXT_INFO
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)
            assertFalse(connection.serverSupportsPing, "Ping should be false when not in initial EXT_INFO")
        } finally {
            connection.close()
        }
    }

    // --- processServerExtInfo: ignored when server did not advertise ext-info-s ---

    @Test
    fun `EXT_INFO from server is ignored when server did not advertise ext-info-s`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = false
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        var authJob: kotlinx.coroutines.Job? = null
        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)

            authJob = backgroundScope.launch(dispatcher) {
                connection.authenticatePassword("user", "pass")
            }
            withTimeout(1000) { server.awaitUserauthRequest() }

            // Send a rogue EXT_INFO even though server never advertised ext-info-s
            server.sendCustomExtInfo(mapOf("server-sig-algs" to "ssh-ed25519".toByteArray(Charsets.US_ASCII)))
            runCurrent()
            assertNull(serverSigAlgs(connection), "server-sig-algs must remain null when EXT_INFO is ignored")
        } finally {
            authJob?.cancel()
            connection.close()
        }
    }

    @Test
    fun `server may update server-sig-algs during user authentication`() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val (clientTransport, serverTransport) = PipedTransport.create()
        val server = FakeSshServer(serverTransport, backgroundScope, dispatcher)
        server.advertiseExtInfo = true
        server.advertisePing = true
        server.start()

        val connection = SshConnection(
            transport = clientTransport,
            hostKeyVerifier = acceptAllVerifier,
            coroutineDispatcher = dispatcher,
        )

        var authJob: kotlinx.coroutines.Job? = null

        try {
            val result = connectInBackground(connection, backgroundScope, dispatcher)
            assertIs<ConnectResult.Success>(result)
            assertTrue(connection.serverSupportsPing, "Initial EXT_INFO should advertise ping")

            authJob = backgroundScope.launch(dispatcher) {
                connection.authenticatePassword("user", "pass")
            }
            withTimeout(1000) { server.awaitUserauthRequest() }
            server.sendCustomExtInfo(mapOf("server-sig-algs" to "rsa-sha2-256".toByteArray(Charsets.US_ASCII)))

            awaitServerSigAlgs(connection, setOf("rsa-sha2-256"))
            assertTrue(connection.serverSupportsPing, "In-auth EXT_INFO must not clear initial-only ping support")
            assertEquals(setOf("rsa-sha2-256"), serverSigAlgs(connection))
        } finally {
            authJob?.cancel()
            connection.close()
        }
    }
}

package org.connectbot.sshlib.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.protocol.SshMsgExtInfo
import org.connectbot.sshlib.transport.PipedTransport
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

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

package org.connectbot.sshlib.example

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.file
import com.github.ajalt.clikt.parameters.types.int
import kotlinx.coroutines.*
import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.ConnectResult
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshSession
import org.slf4j.LoggerFactory

fun main(args: Array<String>) = SshCommand().main(args)

private class SshCommand : CliktCommand(name = "ssh") {
    val debug by option("-d").flag()
    val keyFile by option("-i", help = "Identity file").file(mustExist = true, canBeDir = false)
    val keyPassphrase by option("-K", help = "Passphrase for identity file")
    val port by option("-p", help = "Port").int().default(22)
    val target by argument(help = "user@host")

    override fun run() = runBlocking {
        if (debug) {
            val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger
            root.level = Level.DEBUG
        }
        runSsh()
    }

    private suspend fun CoroutineScope.runSsh() {
        val atIndex = target.indexOf('@')
        if (atIndex < 0) {
            System.err.println("Target must be in user@host format")
            return
        }
        val user = target.substring(0, atIndex)
        val host = target.substring(atIndex + 1)

        val client = SshClient(buildConfig(host))
        try {
            connectAndRun(client, host, user)
        } finally {
            restoreTerminal()
            client.disconnect()
        }
    }

    private fun buildConfig(host: String) = SshClientConfig {
        this.host = host
        this.port = port
        hostKeyVerifier = InteractiveHostKeyVerifier(host, port)
    }

    private suspend fun CoroutineScope.connectAndRun(client: SshClient, host: String, user: String) {
        val connectResult = client.connect()
        if (connectResult !is ConnectResult.Success) {
            System.err.println("Failed to connect to $host:$port: $connectResult")
            return
        }
        if (client.connectionInfo?.isPostQuantumSecure != true) {
            System.err.println("** WARNING: connection is not using a post-quantum key exchange algorithm.")
            System.err.println("** This session may be vulnerable to \"store now, decrypt later\" attacks.")
            System.err.println("** The server may need to be upgraded. See https://openssh.com/pq.html")
        }
        if (!authenticate(client, user)) {
            System.err.println("Authentication failed")
            return
        }
        coroutineScope { runSession(client) }
    }

    private suspend fun authenticate(client: SshClient, user: String): Boolean {
        if (keyFile != null && authenticateWithKey(client, user)) return true
        return authenticateInteractive(client, user)
    }

    private suspend fun authenticateWithKey(client: SshClient, user: String): Boolean {
        val keyData = keyFile!!.readText()
        val console = System.console()
        val passphrase = resolvePassphrase(client, keyData, console)
        if (client.authenticatePublicKey(user, keyData, passphrase) is AuthResult.Success) return true
        if (passphrase != null) return false
        val retry = readPassphrase(console, "Enter passphrase for $keyFile (optional): ")
        return retry.isNotEmpty() && client.authenticatePublicKey(user, keyData, retry) is AuthResult.Success
    }

    private suspend fun resolvePassphrase(client: SshClient, keyData: String, console: java.io.Console?): String? {
        if (keyPassphrase != null) return keyPassphrase
        if (client.isPrivateKeyEncrypted(keyData)) return readPassphrase(console, "Enter passphrase for $keyFile: ")
        return null
    }
}

private suspend fun CoroutineScope.runSession(client: SshClient) {
    val session = client.openSession() ?: run {
        System.err.println("Failed to open session")
        return
    }
    session.requestPty()
    session.requestShell()
    setRawMode()
    Runtime.getRuntime().addShutdownHook(Thread { restoreTerminal() })

    val stdinJob = launch(Dispatchers.IO) { runStdin(session) }
    val stdoutJob = launch(Dispatchers.IO) { runStdout(session) }
    val stderrJob = launch(Dispatchers.IO) { runStderr(session) }

    stdoutJob.join()
    stdinJob.cancel()
    stderrJob.cancel()
    session.close()
}

private suspend fun CoroutineScope.runStdin(session: SshSession) =
    suppressingExceptions {
        val buf = ByteArray(1024)
        while (isActive && pumpStdin(session, buf)) { /* loop */ }
    }

private suspend fun pumpStdin(session: SshSession, buf: ByteArray): Boolean {
    if (System.`in`.available() == 0) { delay(10); return true }
    val n = System.`in`.read(buf)
    if (n < 0) { session.sendEof(); return false }
    session.write(buf.copyOf(n))
    return true
}

private suspend fun CoroutineScope.runStdout(session: SshSession) =
    suppressingExceptions {
        while (isActive) {
            val data = session.read() ?: break
            System.out.write(data)
            System.out.flush()
        }
    }

private suspend fun CoroutineScope.runStderr(session: SshSession) =
    suppressingExceptions {
        while (isActive) {
            val (_, data) = session.readExtended() ?: break
            System.err.write(data)
            System.err.flush()
        }
    }

private inline fun suppressingExceptions(block: () -> Unit) {
    try {
        block()
    } catch (_: Exception) {
    }
}

private var savedStty: String? = null

private fun stty(vararg args: String) =
    ProcessBuilder("stty", *args)
        .redirectInput(ProcessBuilder.Redirect.INHERIT)
        .start()

private fun setRawMode() =
    suppressingExceptions {
        savedStty = String(stty("-g").inputStream.readAllBytes()).trim()
        stty("-icanon", "-echo", "min", "1").waitFor()
    }

private fun restoreTerminal() {
    val stty = savedStty ?: return
    savedStty = null
    suppressingExceptions { stty(stty).waitFor() }
}

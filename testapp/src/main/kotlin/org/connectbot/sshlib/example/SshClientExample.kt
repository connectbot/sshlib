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
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.KnownHostsVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.connectbot.sshlib.SshSession
import org.slf4j.LoggerFactory
import java.io.File
import java.security.MessageDigest
import java.util.Base64

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

        val atIndex = target.indexOf('@')
        if (atIndex < 0) {
            System.err.println("Target must be in user@host format")
            return@runBlocking
        }
        val user = target.substring(0, atIndex)
        val host = target.substring(atIndex + 1)

        val config = SshClientConfig {
            this.host = host
            this.port = port
            hostKeyVerifier = InteractiveHostKeyVerifier(host, port)
        }
        val client = SshClient(config)
        try {
            val connectResult = client.connect()
            if (connectResult !is ConnectResult.Success) {
                System.err.println("Failed to connect to $host:$port: $connectResult")
                return@runBlocking
            }

            if (!authenticate(client, user)) {
                System.err.println("Authentication failed")
                return@runBlocking
            }

            coroutineScope { runSession(client) }
        } catch (e: Exception) {
            System.err.println("Error: ${e.message}")
        } finally {
            restoreTerminal()
            client.disconnect()
        }
    }

    private suspend fun authenticate(client: SshClient, user: String): Boolean {
        if (keyFile != null && authenticateWithKey(client, user)) return true
        return authenticateInteractive(client, user)
    }

    private suspend fun authenticateWithKey(client: SshClient, user: String): Boolean {
        val keyData = keyFile!!.readText()
        val console = System.console()
        var passphrase = keyPassphrase

        if (passphrase == null && client.isPrivateKeyEncrypted(keyData)) {
            passphrase = readPassphrase(console, "Enter passphrase for $keyFile: ")
        }

        if (client.authenticatePublicKey(user, keyData, passphrase) is AuthResult.Success) return true

        if (passphrase != null) return false

        passphrase = readPassphrase(console, "Enter passphrase for $keyFile (optional): ")
        return passphrase.isNotEmpty() && client.authenticatePublicKey(user, keyData, passphrase) is AuthResult.Success
    }
}

private fun readPassphrase(console: java.io.Console?, prompt: String): String =
    if (console != null) {
        String(console.readPassword(prompt))
    } else {
        System.err.print(prompt)
        System.err.flush()
        readlnOrNull() ?: ""
    }

private suspend fun authenticateInteractive(client: SshClient, user: String): Boolean {
    val console = System.console()
    val kbdCallback = object : KeyboardInteractiveCallback {
        override suspend fun onInfoRequest(
            name: String,
            instruction: String,
            prompts: List<KeyboardInteractiveCallback.Prompt>,
            respond: suspend (responses: List<String>) -> Unit
        ) {
            if (name.isNotEmpty()) System.err.println(name)
            if (instruction.isNotEmpty()) System.err.println(instruction)

            val responses = prompts.map { prompt ->
                if (prompt.echo) {
                    System.err.print(prompt.text)
                    System.err.flush()
                    readlnOrNull() ?: ""
                } else {
                    readPassphrase(console, prompt.text)
                }
            }
            respond(responses)
        }
    }

    if (client.authenticateKeyboardInteractive(user, kbdCallback) is AuthResult.Success) return true

    return authenticatePassword(client, user, console)
}

private suspend fun authenticatePassword(client: SshClient, user: String, console: java.io.Console?): Boolean {
    val password = if (console != null) {
        String(console.readPassword("Password: "))
    } else {
        System.err.println("Warning: no console available, reading password from stdin")
        print("Password: ")
        readlnOrNull() ?: return false
    }
    return client.authenticatePassword(user, password) is AuthResult.Success
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

private suspend fun CoroutineScope.runStdin(session: SshSession) {
    try {
        val buf = ByteArray(1024)
        while (isActive) {
            if (System.`in`.available() > 0) {
                val n = System.`in`.read(buf)
                if (n < 0) {
                    session.sendEof()
                    break
                }
                session.write(buf.copyOf(n))
            } else {
                delay(10)
            }
        }
    } catch (_: Exception) {
    }
}

private suspend fun CoroutineScope.runStdout(session: SshSession) {
    try {
        while (isActive) {
            val data = session.read() ?: break
            System.out.write(data)
            System.out.flush()
        }
    } catch (_: Exception) {
    }
}

private suspend fun CoroutineScope.runStderr(session: SshSession) {
    try {
        while (isActive) {
            val (_, data) = session.readExtended() ?: break
            System.err.write(data)
            System.err.flush()
        }
    } catch (_: Exception) {
    }
}

private class InteractiveHostKeyVerifier(
    private val hostname: String,
    private val port: Int
) : HostKeyVerifier {
    private val knownHostsFile = File(System.getProperty("user.home"), ".ssh/known_hosts")
    private val delegate = KnownHostsVerifier(knownHostsFile, hostname, port)

    override suspend fun verify(key: PublicKey): Boolean {
        if (delegate.verify(key)) return true

        val fingerprint = MessageDigest.getInstance("SHA-256").digest(key.encoded)
        val fingerprintStr = Base64.getEncoder().encodeToString(fingerprint).trimEnd('=')

        System.err.println("The authenticity of host '$hostname ($hostname)' can't be established.")
        System.err.println("${key.type} key fingerprint is SHA256:$fingerprintStr.")
        System.err.print("Are you sure you want to continue connecting (yes/no)? ")
        System.err.flush()

        val answer = readlnOrNull()?.trim()?.lowercase()
        if (answer != "yes") return false

        appendToKnownHosts(key)
        System.err.println("Warning: Permanently added '$hostname' to the list of known hosts.")
        return true
    }

    private fun appendToKnownHosts(key: PublicKey) {
        val hostEntry = if (port == 22) hostname else "[$hostname]:$port"
        val keyBase64 = Base64.getEncoder().encodeToString(key.encoded)
        val line = "$hostEntry ${key.type} $keyBase64\n"

        knownHostsFile.parentFile?.mkdirs()
        knownHostsFile.appendText(line)
    }
}

private var savedStty: String? = null

private fun setRawMode() {
    try {
        savedStty =
            String(
                ProcessBuilder("stty", "-g")
                    .redirectInput(ProcessBuilder.Redirect.INHERIT)
                    .start()
                    .inputStream
                    .readAllBytes(),
            ).trim()
        ProcessBuilder("stty", "-icanon", "-echo", "min", "1")
            .redirectInput(ProcessBuilder.Redirect.INHERIT)
            .start()
            .waitFor()
    } catch (_: Exception) {
    }
}

private fun restoreTerminal() {
    val stty = savedStty ?: return
    savedStty = null
    try {
        ProcessBuilder("stty", stty)
            .redirectInput(ProcessBuilder.Redirect.INHERIT)
            .start()
            .waitFor()
    } catch (_: Exception) {
    }
}

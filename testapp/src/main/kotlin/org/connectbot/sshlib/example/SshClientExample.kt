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
import kotlinx.coroutines.*
import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KnownHostsVerifier
import org.connectbot.sshlib.PublicKey
import org.connectbot.sshlib.SshClient
import org.connectbot.sshlib.SshClientConfig
import org.slf4j.LoggerFactory
import java.io.File
import java.security.MessageDigest
import java.util.Base64

fun main(args: Array<String>) =
    runBlocking {
        val parsed = parseArgs(args)
        if (parsed == null) {
            System.err.println("Usage: ssh [-d] <user>@<host> [-p port]")
            return@runBlocking
        }

        if (parsed.debug) {
            val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger
            root.level = Level.DEBUG
        }

        val (user, host, port) = parsed

        val console = System.console()
        val password =
            if (console != null) {
                String(console.readPassword("Password: "))
            } else {
                System.err.println("Warning: no console available, reading password from stdin")
                print("Password: ")
                readlnOrNull() ?: run {
                    System.err.println("No password provided")
                    return@runBlocking
                }
            }

        val config = SshClientConfig {
            this.host = host
            this.port = port
            hostKeyVerifier = InteractiveHostKeyVerifier(host, port)
        }
        val client = SshClient(config)
        try {
            if (!client.connect()) {
                System.err.println("Failed to connect to $host:$port")
                return@runBlocking
            }

            if (!client.authenticatePassword(user, password)) {
                System.err.println("Authentication failed")
                return@runBlocking
            }

            val session = client.openSession()
            if (session == null) {
                System.err.println("Failed to open session")
                return@runBlocking
            }

            session.requestPty()
            session.requestShell()

            setRawMode()
            Runtime.getRuntime().addShutdownHook(Thread { restoreTerminal() })

            val stdinJob =
                launch(Dispatchers.IO) {
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
                                // We could make an FFI call to poll/select here,
                                // but this is good enough for an example
                                delay(10)
                            }
                        }
                    } catch (_: Exception) {
                    }
                }

            val stdoutJob =
                launch(Dispatchers.IO) {
                    try {
                        while (isActive) {
                            val data = session.read() ?: break
                            System.out.write(data)
                            System.out.flush()
                        }
                    } catch (_: Exception) {
                    }
                }

            val stderrJob =
                launch(Dispatchers.IO) {
                    try {
                        while (isActive) {
                            val (_, data) = session.readExtended() ?: break
                            System.err.write(data)
                            System.err.flush()
                        }
                    } catch (_: Exception) {
                    }
                }

            stdoutJob.join()
            stdinJob.cancel()
            stderrJob.cancel()

            session.close()
        } catch (e: Exception) {
            System.err.println("Error: ${e.message}")
        } finally {
            restoreTerminal()
            client.disconnect()
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

private data class ParsedArgs(
    val user: String,
    val host: String,
    val port: Int,
    val debug: Boolean,
)

private fun parseArgs(args: Array<String>): ParsedArgs? {
    if (args.isEmpty()) return null

    var port = 22
    var debug = false
    var target: String? = null

    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "-p" -> {
                if (i + 1 >= args.size) return null
                port = args[++i].toIntOrNull() ?: return null
            }

            "-d" -> {
                debug = true
            }

            else -> {
                target = args[i]
            }
        }
        i++
    }

    if (target == null) return null
    val atIndex = target.indexOf('@')
    if (atIndex < 0) return null

    return ParsedArgs(
        user = target.substring(0, atIndex),
        host = target.substring(atIndex + 1),
        port = port,
        debug = debug,
    )
}

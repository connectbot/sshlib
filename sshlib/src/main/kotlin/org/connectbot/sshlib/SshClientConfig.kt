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

package org.connectbot.sshlib

import org.connectbot.sshlib.crypto.CipherEntry
import org.connectbot.sshlib.crypto.CompressionEntry
import org.connectbot.sshlib.crypto.KexEntry
import org.connectbot.sshlib.crypto.MacEntry
import org.connectbot.sshlib.crypto.SignatureEntry
import org.connectbot.sshlib.transport.IpVersion
import org.connectbot.sshlib.transport.KtorTcpTransportFactory
import org.connectbot.sshlib.transport.TransportFactory

/**
 * Configuration for SSH client connections.
 *
 * Use the builder DSL to create a configuration:
 * ```kotlin
 * // Simple TCP connection (uses KtorTcpTransport by default)
 * val config = SshClientConfig {
 *     host = "example.com"
 *     port = 22
 *     clientVersion = "SSH-2.0-MyClient_1.0"
 * }
 *
 * // Custom transport
 * val config = SshClientConfig {
 *     transportFactory = MyCustomTransportFactory()
 *     clientVersion = "SSH-2.0-MyClient_1.0"
 * }
 * ```
 */
class SshClientConfig private constructor(
    val transportFactory: TransportFactory,
    val clientVersion: String,
    val hostKeyVerifier: HostKeyVerifier,
    val kexAlgorithms: String,
    val hostKeyAlgorithms: String,
    val encryptionAlgorithms: String,
    val macAlgorithms: String,
    internal val compressionAlgorithms: String,
    val preferPasswordAuth: Boolean,
    val rekeyIntervalMs: Long,
    val rekeyBytesLimit: Long,
) {
    class Builder {
        /**
         * Hostname for TCP connections. Used with default KtorTcpTransport.
         * Ignored if [transportFactory] is set explicitly.
         */
        var host: String = ""

        /**
         * Port for TCP connections. Used with default KtorTcpTransport.
         * Ignored if [transportFactory] is set explicitly.
         */
        var port: Int = 22

        /**
         * Client version string sent during SSH handshake.
         */
        var clientVersion: String = "SSH-2.0-CBSSH_1.0"

        /**
         * Host key verifier.
         */
        var hostKeyVerifier: HostKeyVerifier? = null

        /**
         * Custom transport factory. If not set, uses [KtorTcpTransportFactory]
         * with [host], [port], and [ipVersion].
         */
        var transportFactory: TransportFactory? = null

        /**
         * IP version preference for the default TCP transport.
         * Ignored if [transportFactory] is set explicitly.
         */
        var ipVersion: IpVersion = IpVersion.AUTO

        var kexAlgorithms: String = KexEntry.defaultString
        var hostKeyAlgorithms: String = SignatureEntry.defaultString
        var encryptionAlgorithms: String = CipherEntry.defaultString
        var macAlgorithms: String = MacEntry.defaultString

        /**
         * Enable zlib compression. When true, the client offers
         * `zlib@openssh.com,zlib,none`; when false, only `none`.
         */
        var enableCompression: Boolean = false

        /**
         * When true, prefer `password` over `keyboard-interactive` when both are available.
         * By default, `keyboard-interactive` is preferred.
         */
        var preferPasswordAuth: Boolean = false

        /**
         * Re-key after this many milliseconds. Default: 1 hour.
         */
        var rekeyIntervalMs: Long = 3_600_000L

        /**
         * Re-key after this many wire bytes (sent or received). Default: 1 GB.
         */
        var rekeyBytesLimit: Long = 1_073_741_824L

        fun build(): SshClientConfig {
            val factory = transportFactory ?: run {
                require(host.isNotBlank()) { "Host must be specified when using default TCP transport" }
                require(port in 1..65535) { "Port must be between 1 and 65535" }
                KtorTcpTransportFactory(host, port, ipVersion)
            }

            val verifier = hostKeyVerifier
            requireNotNull(verifier) { "hostKeyVerifier must be set" }
            val compressionAlgorithms = if (enableCompression) {
                CompressionEntry.enabledString
            } else {
                CompressionEntry.defaultString
            }

            return SshClientConfig(
                factory,
                clientVersion,
                verifier,
                kexAlgorithms,
                hostKeyAlgorithms,
                encryptionAlgorithms,
                macAlgorithms,
                compressionAlgorithms,
                preferPasswordAuth,
                rekeyIntervalMs,
                rekeyBytesLimit,
            )
        }
    }

    companion object {
        operator fun invoke(block: Builder.() -> Unit): SshClientConfig = Builder().apply(block).build()
    }
}

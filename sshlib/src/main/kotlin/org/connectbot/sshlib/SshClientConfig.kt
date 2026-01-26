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

/**
 * Configuration for SSH client connections.
 *
 * Use the builder DSL to create a configuration:
 * ```kotlin
 * val config = SshClientConfig {
 *     host = "example.com"
 *     port = 22
 *     clientVersion = "SSH-2.0-MyClient_1.0"
 * }
 * ```
 */
class SshClientConfig private constructor(
    val host: String,
    val port: Int,
    val clientVersion: String
) {
    class Builder {
        var host: String = ""
        var port: Int = 22
        var clientVersion: String = "SSH-2.0-SshProtoClient_1.0"

        fun build(): SshClientConfig {
            require(host.isNotBlank()) { "Host must be specified" }
            require(port in 1..65535) { "Port must be between 1 and 65535" }
            return SshClientConfig(host, port, clientVersion)
        }
    }

    companion object {
        operator fun invoke(block: Builder.() -> Unit): SshClientConfig {
            return Builder().apply(block).build()
        }
    }
}

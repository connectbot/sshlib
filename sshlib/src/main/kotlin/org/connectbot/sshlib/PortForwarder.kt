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

import kotlinx.coroutines.runBlocking

/**
 * Handle to an active port forwarding.
 *
 * For local and dynamic forwarding, [boundHost] and [boundPort] are the local bind address.
 * For remote forwarding, they are the remote bind address the server is listening on.
 */
interface PortForwarder : AutoCloseable {
    val boundHost: String
    val boundPort: Int
    val isActive: Boolean
    suspend fun stop()
    override fun close() {
        runBlocking { stop() }
    }
}

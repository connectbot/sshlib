/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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
 * Result of an [AgentProvider] callback.
 *
 * Provider failures are values rather than thrown exceptions so an agent
 * backend failure cannot terminate the SSH connection's packet loop.
 */
sealed interface AgentResult<out T> {
    /** The provider completed successfully with [value]. */
    data class Success<T>(val value: T) : AgentResult<T>

    /** The provider could not complete the request. */
    data class Failure(
        val message: String,
        val cause: Throwable? = null,
    ) : AgentResult<Nothing>
}

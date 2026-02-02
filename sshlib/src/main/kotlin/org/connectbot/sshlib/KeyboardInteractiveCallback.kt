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
 * Callback for keyboard-interactive authentication (RFC 4256).
 *
 * The server sends one or more info requests, each containing prompts
 * that the user must answer. Call [respond] with the answers to send
 * them back to the server.
 */
interface KeyboardInteractiveCallback {
    /**
     * Called when the server sends an info request with prompts.
     *
     * @param name Name of the authentication request (may be empty)
     * @param instruction Instructions for the user (may be empty)
     * @param prompts List of prompts the user must answer
     * @param respond Call this with the list of responses (one per prompt)
     */
    suspend fun onInfoRequest(
        name: String,
        instruction: String,
        prompts: List<Prompt>,
        respond: suspend (responses: List<String>) -> Unit
    )

    data class Prompt(val text: String, val echo: Boolean)
}

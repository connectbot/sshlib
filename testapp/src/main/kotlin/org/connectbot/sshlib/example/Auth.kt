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

import org.connectbot.sshlib.AuthResult
import org.connectbot.sshlib.KeyboardInteractiveCallback
import org.connectbot.sshlib.SshClient
import java.io.Console

internal fun readPassphrase(console: Console?, prompt: String): String =
    if (console != null) {
        String(console.readPassword(prompt))
    } else {
        System.err.print(prompt)
        System.err.flush()
        readlnOrNull() ?: ""
    }

internal class ConsoleKeyboardInteractiveCallback(
    private val console: Console?,
) : KeyboardInteractiveCallback {
    override suspend fun onInfoRequest(
        name: String,
        instruction: String,
        prompts: List<KeyboardInteractiveCallback.Prompt>,
        respond: suspend (responses: List<String>) -> Unit,
    ) {
        if (name.isNotEmpty()) System.err.println(name)
        if (instruction.isNotEmpty()) System.err.println(instruction)
        respond(prompts.map { readPromptResponse(it) })
    }

    private fun readPromptResponse(prompt: KeyboardInteractiveCallback.Prompt): String =
        if (prompt.echo) readEchoPrompt(prompt.text) else readPassphrase(console, prompt.text)

    private fun readEchoPrompt(text: String): String {
        System.err.print(text)
        System.err.flush()
        return readlnOrNull() ?: ""
    }
}

internal suspend fun authenticateInteractive(client: SshClient, user: String): Boolean {
    val console = System.console()
    if (client.authenticateKeyboardInteractive(user, ConsoleKeyboardInteractiveCallback(console)) is AuthResult.Success) return true
    return authenticatePassword(client, user, console)
}

private fun readPassword(console: Console?): String? =
    if (console != null) {
        String(console.readPassword("Password: "))
    } else {
        System.err.println("Warning: no console available, reading password from stdin")
        print("Password: ")
        readlnOrNull()
    }

internal suspend fun authenticatePassword(client: SshClient, user: String, console: Console?): Boolean {
    val password = readPassword(console) ?: return false
    return client.authenticatePassword(user, password) is AuthResult.Success
}

/*
 * ConnectBot SSH Library
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

package org.connectbot.sshlib.client

internal sealed class AuthMethod {
    data object Password : AuthMethod()
    data object PublicKey : AuthMethod()
    data object KeyboardInteractive : AuthMethod()
    data class Unknown(val name: String) : AuthMethod()

    companion object {
        fun fromString(name: String): AuthMethod = when (name) {
            "password" -> Password
            "publickey" -> PublicKey
            "keyboard-interactive" -> KeyboardInteractive
            else -> Unknown(name)
        }

        fun toSshName(method: AuthMethod): String = when (method) {
            is Password -> "password"
            is PublicKey -> "publickey"
            is KeyboardInteractive -> "keyboard-interactive"
            is Unknown -> method.name
        }
    }
}

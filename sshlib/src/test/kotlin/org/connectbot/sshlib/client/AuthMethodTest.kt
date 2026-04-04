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
package org.connectbot.sshlib.client

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class AuthMethodTest {
    @Test
    fun `fromString returns Password for password`() {
        assertEquals(AuthMethod.Password, AuthMethod.fromString("password"))
    }

    @Test
    fun `fromString returns PublicKey for publickey`() {
        assertEquals(AuthMethod.PublicKey, AuthMethod.fromString("publickey"))
    }

    @Test
    fun `fromString returns KeyboardInteractive for keyboard-interactive`() {
        assertEquals(AuthMethod.KeyboardInteractive, AuthMethod.fromString("keyboard-interactive"))
    }

    @Test
    fun `fromString returns Unknown for unrecognised method`() {
        assertEquals(AuthMethod.Unknown("gssapi-with-mic"), AuthMethod.fromString("gssapi-with-mic"))
    }

    @Test
    fun `toSshName round-trips all known methods`() {
        listOf(
            AuthMethod.Password to "password",
            AuthMethod.PublicKey to "publickey",
            AuthMethod.KeyboardInteractive to "keyboard-interactive",
            AuthMethod.Unknown("gssapi-with-mic") to "gssapi-with-mic",
        ).forEach { (method, name) ->
            assertEquals(name, AuthMethod.toSshName(method))
        }
    }
}

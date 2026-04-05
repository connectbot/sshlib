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

class SelectPasswordMethodsTest {

    @Test
    fun `only password offered - preferPasswordAuth false - uses password`() {
        val result = selectPasswordMethods(setOf("password"), preferPasswordAuth = false)
        assertEquals(listOf(AuthMethod.Password), result)
    }

    @Test
    fun `only password offered - preferPasswordAuth true - uses password`() {
        val result = selectPasswordMethods(setOf("password"), preferPasswordAuth = true)
        assertEquals(listOf(AuthMethod.Password), result)
    }

    @Test
    fun `only keyboard-interactive offered - preferPasswordAuth false - uses keyboard-interactive`() {
        val result = selectPasswordMethods(setOf("keyboard-interactive"), preferPasswordAuth = false)
        assertEquals(listOf(AuthMethod.KeyboardInteractive), result)
    }

    @Test
    fun `only keyboard-interactive offered - preferPasswordAuth true - uses keyboard-interactive`() {
        val result = selectPasswordMethods(setOf("keyboard-interactive"), preferPasswordAuth = true)
        assertEquals(listOf(AuthMethod.KeyboardInteractive), result)
    }

    @Test
    fun `both offered - preferPasswordAuth false - keyboard-interactive is preferred`() {
        val result = selectPasswordMethods(setOf("keyboard-interactive", "password"), preferPasswordAuth = false)
        assertEquals(listOf(AuthMethod.KeyboardInteractive), result)
    }

    @Test
    fun `both offered - preferPasswordAuth true - password is used`() {
        val result = selectPasswordMethods(setOf("keyboard-interactive", "password"), preferPasswordAuth = true)
        assertEquals(listOf(AuthMethod.Password), result)
    }

    @Test
    fun `neither offered - returns empty`() {
        val result = selectPasswordMethods(setOf("publickey"), preferPasswordAuth = false)
        assertEquals(emptyList<AuthMethod>(), result)
    }

    @Test
    fun `unknown method in set - ignored by selectPasswordMethods`() {
        val result = selectPasswordMethods(setOf("gssapi-with-mic"), preferPasswordAuth = false)
        assertEquals(emptyList<AuthMethod>(), result)
    }
}

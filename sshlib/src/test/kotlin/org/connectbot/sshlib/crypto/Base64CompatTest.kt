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

package org.connectbot.sshlib.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class Base64CompatTest {

    @Test
    fun `encode produces standard base64 without padding`() {
        // "Man" -> "TWFu" (no padding needed)
        val result = Base64Compat.encode("Man".toByteArray(Charsets.US_ASCII))
        assertEquals("TWFu", result)
    }

    @Test
    fun `encode strips padding when input length requires it`() {
        // "Ma" -> "TWE=" in padded base64, "TWE" without
        val result = Base64Compat.encode("Ma".toByteArray(Charsets.US_ASCII))
        assertFalse(result.contains('='), "encode() must not contain '=' padding")
        assertEquals("TWE", result)
    }

    @Test
    fun `encode produces no line breaks`() {
        val data = ByteArray(100) { it.toByte() }
        val result = Base64Compat.encode(data)
        assertFalse(result.contains('\n'), "encode() must not contain newlines")
        assertFalse(result.contains('\r'), "encode() must not contain carriage returns")
    }

    @Test
    fun `encodeWithPadding produces standard base64 with padding`() {
        // "Ma" -> "TWE=" with padding
        val result = Base64Compat.encodeWithPadding("Ma".toByteArray(Charsets.US_ASCII))
        assertEquals("TWE=", result)
    }

    @Test
    fun `encodeWithPadding produces no line breaks`() {
        val data = ByteArray(100) { it.toByte() }
        val result = Base64Compat.encodeWithPadding(data)
        assertFalse(result.contains('\n'), "encodeWithPadding() must not contain newlines")
        assertFalse(result.contains('\r'), "encodeWithPadding() must not contain carriage returns")
    }

    @Test
    fun `decode round-trips with encode`() {
        val original = "Hello, SSH world!".toByteArray(Charsets.UTF_8)
        val encoded = Base64Compat.encode(original)
        val decoded = Base64Compat.decode(encoded)
        assertArrayEquals(original, decoded)
    }

    @Test
    fun `decode round-trips with encodeWithPadding`() {
        val original = "Hello, SSH world!".toByteArray(Charsets.UTF_8)
        val encoded = Base64Compat.encodeWithPadding(original)
        assertTrue(encoded.endsWith("=") || encoded.length % 4 == 0)
        val decoded = Base64Compat.decode(encoded)
        assertArrayEquals(original, decoded)
    }

    @Test
    fun `decode handles input with padding`() {
        val decoded = Base64Compat.decode("TWE=")
        assertArrayEquals("Ma".toByteArray(Charsets.US_ASCII), decoded)
    }

    @Test
    fun `decode handles input without padding`() {
        val decoded = Base64Compat.decode("TWE")
        assertArrayEquals("Ma".toByteArray(Charsets.US_ASCII), decoded)
    }

    @Test
    fun `encode empty array produces empty string`() {
        assertEquals("", Base64Compat.encode(ByteArray(0)))
    }

    @Test
    fun `decode empty string produces empty array`() {
        assertArrayEquals(ByteArray(0), Base64Compat.decode(""))
    }
}

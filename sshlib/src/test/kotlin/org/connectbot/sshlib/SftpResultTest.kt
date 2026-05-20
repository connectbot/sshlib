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

package org.connectbot.sshlib

import nl.jqno.equalsverifier.EqualsVerifier
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.fail

class SftpResultTest {

    @Test
    fun `Success equals and hashCode`() {
        EqualsVerifier.forClass(SftpResult.Success::class.java)
            .verify()
    }

    @Test
    fun `ServerError equals and hashCode`() {
        EqualsVerifier.forClass(SftpResult.ServerError::class.java)
            .verify()
    }

    @Test
    fun `ProtocolError equals and hashCode`() {
        EqualsVerifier.forClass(SftpResult.ProtocolError::class.java)
            .verify()
    }

    @Test
    fun `IoError equals and hashCode`() {
        EqualsVerifier.forClass(SftpResult.IoError::class.java)
            .withPrefabValues(
                Throwable::class.java,
                IllegalStateException("first"),
                IllegalArgumentException("second"),
            )
            .verify()
    }

    @Test
    fun `getOrNull returns value only for success`() {
        assertEquals("ok", SftpResult.Success("ok").getOrNull())
        assertNull(SftpResult.ServerError(SftpStatusCode.NO_SUCH_FILE, "missing").getOrNull())
        assertNull(SftpResult.ProtocolError("bad packet").getOrNull())
        assertNull(SftpResult.IoError(IllegalStateException("closed")).getOrNull())
    }

    @Test
    fun `getOrThrow returns success value`() {
        assertEquals(42, SftpResult.Success(42).getOrThrow())
    }

    @Test
    fun `getOrThrow converts server error to SftpException`() {
        val exception = expectSftpException {
            SftpResult.ServerError(SftpStatusCode.PERMISSION_DENIED, "denied").getOrThrow()
        }

        assertEquals(SftpStatusCode.PERMISSION_DENIED, exception.statusCode)
        assertEquals("denied", exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `getOrThrow converts protocol error to bad message`() {
        val exception = expectSftpException {
            SftpResult.ProtocolError("unexpected packet").getOrThrow()
        }

        assertEquals(SftpStatusCode.BAD_MESSAGE, exception.statusCode)
        assertEquals("unexpected packet", exception.message)
        assertNull(exception.cause)
    }

    @Test
    fun `getOrThrow converts io error to failure preserving cause`() {
        val cause = IllegalStateException("socket closed")

        val exception = expectSftpException {
            SftpResult.IoError(cause).getOrThrow()
        }

        assertEquals(SftpStatusCode.FAILURE, exception.statusCode)
        assertEquals("socket closed", exception.message)
        assertSame(cause, exception.cause)
    }

    @Test
    fun `getOrThrow uses fallback message for io error without message`() {
        val cause = object : RuntimeException() {}

        val exception = expectSftpException {
            SftpResult.IoError(cause).getOrThrow()
        }

        assertEquals(SftpStatusCode.FAILURE, exception.statusCode)
        assertEquals("I/O error", exception.message)
        assertSame(cause, exception.cause)
    }

    private inline fun expectSftpException(block: () -> Unit): SftpException {
        try {
            block()
        } catch (e: SftpException) {
            return e
        }
        fail("Expected SftpException")
    }
}

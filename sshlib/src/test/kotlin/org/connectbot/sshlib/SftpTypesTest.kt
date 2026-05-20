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

class SftpTypesTest {

    @Test
    fun `SftpFileHandle equals and hashCode`() {
        EqualsVerifier.forClass(SftpFileHandle::class.java)
            .withPrefabValues(ByteArray::class.java, byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
            .verify()
    }

    @Test
    fun `SftpAttributes equals and hashCode`() {
        EqualsVerifier.forClass(SftpAttributes::class.java)
            .verify()
    }

    @Test
    fun `SftpDirectoryEntry equals and hashCode`() {
        EqualsVerifier.forClass(SftpDirectoryEntry::class.java)
            .verify()
    }

    @Test
    fun `SftpStatusCode maps known and unknown status codes`() {
        assertEquals(SftpStatusCode.OK, SftpStatusCode.fromCode(0))
        assertEquals(SftpStatusCode.EOF, SftpStatusCode.fromCode(1))
        assertEquals(SftpStatusCode.NO_SUCH_FILE, SftpStatusCode.fromCode(2))
        assertEquals(SftpStatusCode.PERMISSION_DENIED, SftpStatusCode.fromCode(3))
        assertEquals(SftpStatusCode.FAILURE, SftpStatusCode.fromCode(4))
        assertEquals(SftpStatusCode.BAD_MESSAGE, SftpStatusCode.fromCode(5))
        assertEquals(SftpStatusCode.NO_CONNECTION, SftpStatusCode.fromCode(6))
        assertEquals(SftpStatusCode.CONNECTION_LOST, SftpStatusCode.fromCode(7))
        assertEquals(SftpStatusCode.OP_UNSUPPORTED, SftpStatusCode.fromCode(8))
        assertEquals(SftpStatusCode.FAILURE, SftpStatusCode.fromCode(-1))
        assertEquals(SftpStatusCode.FAILURE, SftpStatusCode.fromCode(9))
    }
}

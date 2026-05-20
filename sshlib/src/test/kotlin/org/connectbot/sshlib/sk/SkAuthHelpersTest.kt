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

package org.connectbot.sshlib.sk

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class SkAuthHelpersTest {

    @Test
    fun `buildAuthPublicKey sets algorithm name and encodes blob`() {
        val rawKey = ByteArray(32) { it.toByte() }
        val authKey = SkAuthHelpers.buildAuthPublicKey(SkAlgorithm.ED25519, rawKey, "ssh:")

        assertEquals("sk-ssh-ed25519@openssh.com", authKey.algorithmName)
        val expectedBlob = SkPublicKeyEncoder.encode(SkAlgorithm.ED25519, rawKey, "ssh:")
        assertContentEquals(expectedBlob, authKey.publicKeyBlob)
    }

    @Test
    fun `buildAuthPublicKey works for ECDSA-P256`() {
        val ecPoint = ByteArray(65).also { it[0] = 0x04 }
        val authKey = SkAuthHelpers.buildAuthPublicKey(SkAlgorithm.ECDSA_P256, ecPoint, "ssh:rp")
        assertEquals("sk-ecdsa-sha2-nistp256@openssh.com", authKey.algorithmName)
        assertContentEquals(
            SkPublicKeyEncoder.encode(SkAlgorithm.ECDSA_P256, ecPoint, "ssh:rp"),
            authKey.publicKeyBlob,
        )
    }
}

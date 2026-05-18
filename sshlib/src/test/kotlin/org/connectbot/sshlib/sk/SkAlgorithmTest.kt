/*
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

import nl.jqno.equalsverifier.EqualsVerifier
import nl.jqno.equalsverifier.Warning
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SkAlgorithmTest {

    @Test
    fun `fromSshName matches both algorithms`() {
        assertEquals(SkAlgorithm.ED25519, SkAlgorithm.fromSshName("sk-ssh-ed25519@openssh.com"))
        assertEquals(SkAlgorithm.ECDSA_P256, SkAlgorithm.fromSshName("sk-ecdsa-sha2-nistp256@openssh.com"))
    }

    @Test
    fun `fromSshName rejects non-SK names`() {
        assertNull(SkAlgorithm.fromSshName("ssh-ed25519"))
        assertNull(SkAlgorithm.fromSshName("rsa-sha2-256"))
        assertNull(SkAlgorithm.fromSshName(""))
    }

    @Test
    fun `isSkAlgorithm classifies names`() {
        assertTrue(SkAlgorithm.isSkAlgorithm("sk-ssh-ed25519@openssh.com"))
        assertTrue(SkAlgorithm.isSkAlgorithm("sk-ecdsa-sha2-nistp256@openssh.com"))
        assertFalse(SkAlgorithm.isSkAlgorithm("ssh-ed25519"))
        // Other SK variants (e.g. webauthn) intentionally not handled by this helper
        assertFalse(SkAlgorithm.isSkAlgorithm("webauthn-sk-ecdsa-sha2-nistp256@openssh.com"))
    }

    @Test
    fun `SkPublicKey respects equals and hashCode contract`() {
        EqualsVerifier.forClass(SkPublicKey::class.java)
            .suppress(Warning.SURROGATE_KEY)
            .verify()
    }
}

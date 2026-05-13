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

package org.connectbot.sshlib

import java.security.KeyPairGenerator
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SshSigningSkTest {

    @Test
    fun `sign rejects sk-ssh-ed25519 with a clear message`() {
        val e = assertFailsWith<SshException> {
            SshSigning.sign(
                algorithmName = "sk-ssh-ed25519@openssh.com",
                privateKeyData = "ignored",
                passphrase = null,
                dataToSign = byteArrayOf(0x01),
            )
        }
        assertTrue(e.message!!.contains("AuthHandler"), "error should point to AuthHandler API: ${e.message}")
        assertTrue(e.message!!.contains("SkSignatureBlob"), "error should mention SkSignatureBlob: ${e.message}")
    }

    @Test
    fun `sign rejects sk-ecdsa-sha2-nistp256 with a clear message`() {
        val e = assertFailsWith<SshException> {
            SshSigning.sign(
                algorithmName = "sk-ecdsa-sha2-nistp256@openssh.com",
                privateKeyData = "ignored",
                passphrase = null,
                dataToSign = byteArrayOf(0x01),
            )
        }
        assertTrue(e.message!!.contains("AuthHandler"))
    }

    @Test
    fun `signWithKeyPair rejects sk- algorithm names`() {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        assertFailsWith<SshException> {
            SshSigning.signWithKeyPair(
                algorithmName = "sk-ssh-ed25519@openssh.com",
                keyPair = keyPair,
                dataToSign = byteArrayOf(0x01),
            )
        }
    }
}

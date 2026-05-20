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

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ConnectionInfoTest {

    private fun info(kex: String) = ConnectionInfo(
        kexAlgorithm = kex,
        serverHostKeyAlgorithm = "ssh-ed25519",
        encryptionAlgorithmC2S = "aes256-gcm@openssh.com",
        encryptionAlgorithmS2C = "aes256-gcm@openssh.com",
        macAlgorithmC2S = null,
        macAlgorithmS2C = null,
    )

    @Test
    fun `isPostQuantumSecure is true for mlkem768x25519-sha256`() {
        assertTrue(info("mlkem768x25519-sha256").isPostQuantumSecure)
    }

    @Test
    fun `isPostQuantumSecure is false for curve25519-sha256`() {
        assertFalse(info("curve25519-sha256").isPostQuantumSecure)
    }

    @Test
    fun `isPostQuantumSecure is false for ecdh-sha2-nistp256`() {
        assertFalse(info("ecdh-sha2-nistp256").isPostQuantumSecure)
    }

    @Test
    fun `isPostQuantumSecure is false for unknown algorithm`() {
        assertFalse(info("unknown-kex").isPostQuantumSecure)
    }
}

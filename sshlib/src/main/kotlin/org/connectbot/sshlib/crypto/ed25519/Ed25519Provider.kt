/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
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

@file:Suppress("DEPRECATION", "removal")

package org.connectbot.sshlib.crypto.ed25519

import java.security.AccessController
import java.security.PrivilegedAction
import java.security.Provider
import java.security.Security

// Android only has the Provider(String, double, String) constructor.
internal class Ed25519Provider : Provider(NAME, 1.0, "ConnectBot Ed25519 JCA Provider") {
    init {
        AccessController.doPrivileged(
            PrivilegedAction {
                setup()
                null
            },
        )
    }

    private fun setup() {
        val packageName = Ed25519Provider::class.java.`package`.name
        put("KeyFactory.$KEY_ALGORITHM", "$packageName.Ed25519KeyFactory")
        put("KeyPairGenerator.$KEY_ALGORITHM", "$packageName.Ed25519KeyPairGenerator")

        // OID aliases: id-Ed25519 OBJECT IDENTIFIER ::= { 1 3 101 112 }
        put("Alg.Alias.KeyFactory.1.3.101.112", KEY_ALGORITHM)
        put("Alg.Alias.KeyFactory.EdDSA", KEY_ALGORITHM)
        put("Alg.Alias.KeyFactory.OID.1.3.101.112", KEY_ALGORITHM)
        put("Alg.Alias.KeyPairGenerator.1.3.101.112", KEY_ALGORITHM)
        put("Alg.Alias.KeyPairGenerator.EdDSA", KEY_ALGORITHM)
        put("Alg.Alias.KeyPairGenerator.OID.1.3.101.112", KEY_ALGORITHM)
    }

    companion object {
        const val NAME = "ConnectBot Ed25519 Provider"
        const val KEY_ALGORITHM = "Ed25519"

        private val initLock = Any()
        private var initialized = false

        fun insertIfNeeded() {
            synchronized(initLock) {
                if (!initialized) {
                    Security.insertProviderAt(Ed25519Provider(), 1)
                    initialized = true
                }
            }
        }
    }
}

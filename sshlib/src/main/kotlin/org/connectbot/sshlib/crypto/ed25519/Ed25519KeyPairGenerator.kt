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

package org.connectbot.sshlib.crypto.ed25519

import com.google.crypto.tink.subtle.Ed25519Sign
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.KeyPairGeneratorSpi
import java.security.SecureRandom

internal class Ed25519KeyPairGenerator : KeyPairGeneratorSpi() {
    override fun initialize(keySize: Int, secureRandom: SecureRandom) {
        // ignored
    }

    override fun generateKeyPair(): KeyPair {
        try {
            val kp = Ed25519Sign.KeyPair.newKeyPair()
            return KeyPair(Ed25519PublicKey(kp.publicKey), Ed25519PrivateKey(kp.privateKey))
        } catch (e: GeneralSecurityException) {
            throw IllegalStateException(e)
        }
    }
}

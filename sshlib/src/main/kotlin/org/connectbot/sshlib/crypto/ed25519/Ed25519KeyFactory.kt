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

package org.connectbot.sshlib.crypto.ed25519

import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyFactorySpi
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

internal class Ed25519KeyFactory : KeyFactorySpi() {
    override fun engineGeneratePublic(keySpec: KeySpec): PublicKey {
        if (keySpec is X509EncodedKeySpec) {
            return Ed25519PublicKey(keySpec)
        }
        throw InvalidKeySpecException("Unrecognized key spec: ${keySpec.javaClass}")
    }

    override fun engineGeneratePrivate(keySpec: KeySpec): PrivateKey {
        if (keySpec is PKCS8EncodedKeySpec) {
            return Ed25519PrivateKey(keySpec)
        }
        throw InvalidKeySpecException("Unrecognized key spec: ${keySpec.javaClass}")
    }

    override fun <T : KeySpec> engineGetKeySpec(key: Key, keySpec: Class<T>): T = throw InvalidKeySpecException("Not implemented: $key $keySpec")

    override fun engineTranslateKey(key: Key): Key {
        if (key is Ed25519PublicKey || key is Ed25519PrivateKey) {
            return key
        }

        if (key is PublicKey && key.format == "X.509") {
            try {
                return Ed25519PublicKey(X509EncodedKeySpec(key.encoded))
            } catch (e: InvalidKeySpecException) {
                throw InvalidKeyException(e)
            }
        }

        if (key is PrivateKey && key.format == "PKCS#8") {
            try {
                return Ed25519PrivateKey(PKCS8EncodedKeySpec(key.encoded))
            } catch (e: InvalidKeySpecException) {
                throw InvalidKeyException(e)
            }
        }

        throw InvalidKeyException("Could not convert EdDSA key from key class ${key.javaClass}")
    }
}

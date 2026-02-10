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

import org.connectbot.sshlib.crypto.DerReader
import org.connectbot.sshlib.crypto.encodeDer
import java.math.BigInteger
import java.security.PrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import javax.security.auth.DestroyFailedException
import javax.security.auth.Destroyable

internal class Ed25519PrivateKey : PrivateKey, Destroyable {
    private val seed: ByteArray
    private var destroyed = false

    constructor(seed: ByteArray) {
        this.seed = seed
    }

    constructor(keySpec: PKCS8EncodedKeySpec) {
        this.seed = decode(keySpec)
    }

    override fun getAlgorithm(): String = "EdDSA"

    override fun getFormat(): String = "PKCS#8"

    fun getSeed(): ByteArray = seed

    override fun getEncoded(): ByteArray = encodeDer {
        sequence {
            integer(BigInteger.ZERO)
            sequence {
                objectIdentifier(ED25519_OID)
            }
            octetString(encodeDer { octetString(seed) })
        }
    }

    override fun hashCode(): Int = seed.contentHashCode()

    override fun equals(other: Any?): Boolean {
        if (other !is Ed25519PrivateKey) return false
        // Constant-time comparison
        if (seed.size != other.seed.size) return false
        var diff = 0
        for (i in seed.indices) {
            diff = diff or (seed[i].toInt() xor other.seed[i].toInt())
        }
        return diff == 0
    }

    override fun destroy() {
        seed.fill(0)
        destroyed = true
    }

    override fun isDestroyed(): Boolean = destroyed

    companion object {
        private val ED25519_OID = byteArrayOf(0x2b, 0x65, 0x70)
        private const val KEY_BYTES_LENGTH = 32

        private fun decode(keySpec: PKCS8EncodedKeySpec): ByteArray {
            val encoded = keySpec.encoded

            if (encoded.size == KEY_BYTES_LENGTH) {
                return encoded
            }

            try {
                val reader = DerReader(encoded)
                return reader.readSequence { seq ->
                    val version = seq.readInteger()
                    if (version != BigInteger.ZERO) {
                        throw InvalidKeySpecException("Unsupported PKCS#8 version: $version")
                    }
                    seq.readSequence { algId ->
                        val oid = algId.readObjectIdentifier()
                        if (!oid.contentEquals(ED25519_OID)) {
                            throw InvalidKeySpecException("Expected Ed25519 OID, got unexpected OID")
                        }
                    }
                    val privateKeyOctetString = seq.readOctetString()
                    val innerReader = DerReader(privateKeyOctetString)
                    val seed = innerReader.readOctetString()
                    if (seed.size != KEY_BYTES_LENGTH) {
                        throw InvalidKeySpecException("Expected $KEY_BYTES_LENGTH byte seed, got ${seed.size}")
                    }
                    seed
                }
            } catch (e: Exception) {
                if (e is InvalidKeySpecException) throw e
                throw InvalidKeySpecException("Key was not encoded correctly", e)
            }
        }
    }
}

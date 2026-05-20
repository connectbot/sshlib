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

import org.connectbot.sshlib.crypto.DerReader
import org.connectbot.sshlib.crypto.encodeDer
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec

internal class Ed25519PublicKey : PublicKey {
    private val keyBytes: ByteArray

    constructor(keyBytes: ByteArray) {
        this.keyBytes = keyBytes
    }

    constructor(keySpec: X509EncodedKeySpec) {
        this.keyBytes = decode(keySpec.encoded)
    }

    override fun getAlgorithm(): String = "EdDSA"

    override fun getFormat(): String = "X.509"

    override fun getEncoded(): ByteArray = encodeDer {
        sequence {
            sequence {
                objectIdentifier(ED25519_OID)
            }
            bitString(keyBytes)
        }
    }

    fun getAbyte(): ByteArray = keyBytes

    override fun hashCode(): Int = keyBytes.contentHashCode()

    override fun equals(other: Any?): Boolean {
        if (other !is Ed25519PublicKey) return false
        return keyBytes.contentEquals(other.keyBytes)
    }

    companion object {
        private val ED25519_OID = byteArrayOf(0x2b, 0x65, 0x70)
        private const val KEY_BYTES_LENGTH = 32

        private fun decode(input: ByteArray): ByteArray {
            if (input.size == KEY_BYTES_LENGTH) {
                return input
            }

            try {
                val reader = DerReader(input)
                return reader.readSequence { seq ->
                    seq.readSequence { algId ->
                        val oid = algId.readObjectIdentifier()
                        if (!oid.contentEquals(ED25519_OID)) {
                            throw InvalidKeySpecException("Expected Ed25519 OID, got unexpected OID")
                        }
                    }
                    val publicKeyBits = seq.readBitString()
                    if (publicKeyBits.size != KEY_BYTES_LENGTH) {
                        throw InvalidKeySpecException("Expected $KEY_BYTES_LENGTH byte public key, got ${publicKeyBits.size}")
                    }
                    publicKeyBits
                }
            } catch (e: Exception) {
                if (e is InvalidKeySpecException) throw e
                throw InvalidKeySpecException("Key was not encoded correctly", e)
            }
        }
    }
}

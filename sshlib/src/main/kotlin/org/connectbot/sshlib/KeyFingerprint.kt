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

package org.connectbot.sshlib

import org.connectbot.sshlib.crypto.Base64Compat
import java.security.MessageDigest

/**
 * SSH key fingerprint utilities.
 *
 * Produces OpenSSH-compatible fingerprints in SHA-256, MD5, Bubble-Babble,
 * and ASCII randomart formats.
 */
object KeyFingerprint {

    private val VOWELS = charArrayOf('a', 'e', 'i', 'o', 'u', 'y')
    private val CONSONANTS = charArrayOf(
        'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
        'n', 'p', 'r', 's', 't', 'v', 'z', 'x',
    )

    private const val FLDBASE = 8
    private const val FLDSIZE_Y = FLDBASE + 1
    private const val FLDSIZE_X = FLDBASE * 2 + 1
    private const val AUGMENTATION_STRING = " .o+=*BOX@%&#/^SE"

    /**
     * SHA-256 fingerprint in Base64 format (OpenSSH default).
     *
     * @param publicKeyBlob SSH wire-format public key blob
     * @return e.g. "SHA256:kKbdmK+Vqeu/XRnlPNOMuAgG7cIeii3bYsZTY6tY1xM"
     */
    fun sha256(publicKeyBlob: ByteArray): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(publicKeyBlob)
        val base64 = Base64Compat.encode(hash)
        return "SHA256:$base64"
    }

    /**
     * MD5 fingerprint in hex-colon format.
     *
     * @param publicKeyBlob SSH wire-format public key blob
     * @return e.g. "7b:7f:ef:47:43:38:05:39:1d:23:be:1f:f9:8a:cc:a3"
     */
    fun md5(publicKeyBlob: ByteArray): String {
        val hash = MessageDigest.getInstance("MD5").digest(publicKeyBlob)
        return hash.joinToString(":") { "%02x".format(it) }
    }

    /**
     * Bubble-Babble fingerprint (phonetic encoding of SHA-1 hash).
     *
     * @param publicKeyBlob SSH wire-format public key blob
     * @return e.g. "xitiz-ritah-gykez..."
     */
    fun bubblebabble(publicKeyBlob: ByteArray): String {
        val hash = MessageDigest.getInstance("SHA-1").digest(publicKeyBlob)
        return toBubblebabble(hash)
    }

    /**
     * ASCII randomart visualization (SHA-256 based, OpenSSH compatible).
     *
     * @param publicKeyBlob SSH wire-format public key blob
     * @param keyType key type label (e.g. "RSA", "ED25519")
     * @param keySize key size in bits
     * @return multi-line ASCII art string
     */
    fun randomArt(publicKeyBlob: ByteArray, keyType: String, keySize: Int): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(publicKeyBlob)
        return toRandomArt(hash, keyType, keySize)
    }

    private fun toBubblebabble(hash: ByteArray): String {
        val sb = StringBuilder()
        var seed = 1
        val rounds = hash.size / 2 + 1

        sb.append('x')

        for (i in 0 until rounds) {
            if (i < hash.size / 2) {
                val byte1 = hash[2 * i].toInt() and 0xff
                val byte2 = hash[2 * i + 1].toInt() and 0xff

                sb.append(VOWELS[(((byte1 shr 6) and 3) + seed) % 6])
                sb.append(CONSONANTS[(byte1 shr 2) and 15])
                sb.append(VOWELS[((byte1 and 3) + seed / 6) % 6])
                sb.append(CONSONANTS[(byte2 shr 4) and 15])
                sb.append('-')
                sb.append(CONSONANTS[byte2 and 15])

                seed = (seed * 5 + byte1 * 7 + byte2) % 36
            } else {
                sb.append(VOWELS[seed % 6])
                sb.append(CONSONANTS[16])
                sb.append(VOWELS[seed / 6])
            }
        }

        sb.append('x')
        return sb.toString()
    }

    private fun toRandomArt(hash: ByteArray, keyType: String, keySize: Int): String {
        val field = Array(FLDSIZE_X) { IntArray(FLDSIZE_Y) }

        var x = FLDSIZE_X / 2
        var y = FLDSIZE_Y / 2

        for (b in hash) {
            var input = b.toInt() and 0xff
            repeat(4) {
                x += if (input and 0x1 != 0) 1 else -1
                y += if (input and 0x2 != 0) 1 else -1

                x = x.coerceIn(0, FLDSIZE_X - 1)
                y = y.coerceIn(0, FLDSIZE_Y - 1)

                if (field[x][y] < AUGMENTATION_STRING.length - 2) {
                    field[x][y]++
                }

                input = input shr 2
            }
        }

        field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = AUGMENTATION_STRING.length - 2
        field[x][y] = AUGMENTATION_STRING.length - 1

        val sb = StringBuilder()
        val header = "[$keyType $keySize]"
        val headerPadding = (FLDSIZE_X - header.length) / 2

        sb.append('+')
        repeat(headerPadding) { sb.append('-') }
        sb.append(header)
        repeat(FLDSIZE_X - headerPadding - header.length) { sb.append('-') }
        sb.append('+')
        sb.append('\n')

        for (j in 0 until FLDSIZE_Y) {
            sb.append('|')
            for (i in 0 until FLDSIZE_X) {
                sb.append(AUGMENTATION_STRING[field[i][j]])
            }
            sb.append('|')
            if (j < FLDSIZE_Y - 1) {
                sb.append('\n')
            }
        }

        sb.append('\n')
        sb.append('+')
        val footerPadding = (FLDSIZE_X - 8) / 2
        repeat(footerPadding) { sb.append('-') }
        sb.append("[SHA256]")
        repeat(FLDSIZE_X - footerPadding - 8) { sb.append('-') }
        sb.append('+')

        return sb.toString()
    }
}

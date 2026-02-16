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

import org.junit.jupiter.api.Test
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KeyFingerprintTest {

    private fun loadPublicKeyBlob(resourcePath: String): ByteArray {
        val line = javaClass.getResourceAsStream("/keys/$resourcePath")!!
            .bufferedReader().readText().trim()
        val base64Part = line.split(" ")[1]
        return Base64.getDecoder().decode(base64Part)
    }

    // SHA-256 tests (golden values from ssh-keygen -lf -E sha256)

    @Test
    fun `sha256 RSA`() {
        val blob = loadPublicKeyBlob("rsa_unencrypted.pub")
        assertEquals("SHA256:NE9IPkwm6/WOVWI2tpE2z3qeRlOiB6eXwuO/oF+u8Ck", KeyFingerprint.sha256(blob))
    }

    @Test
    fun `sha256 Ed25519`() {
        val blob = loadPublicKeyBlob("ed25519_unencrypted.pub")
        assertEquals("SHA256:lmNuPlCF2Zkeqn37l+92neW42Mb9MjfwlTZ9uFL2YNY", KeyFingerprint.sha256(blob))
    }

    @Test
    fun `sha256 ECDSA 256`() {
        val blob = loadPublicKeyBlob("ecdsa256_unencrypted.pub")
        assertEquals("SHA256:pY/XogUV2q6GFYoLh8TAvadCNq4gjoj2CWPqLojP9Po", KeyFingerprint.sha256(blob))
    }

    // MD5 tests (golden values from ssh-keygen -lf -E md5)

    @Test
    fun `md5 RSA`() {
        val blob = loadPublicKeyBlob("rsa_unencrypted.pub")
        assertEquals("00:1d:be:00:84:8b:ed:7b:f2:08:82:b2:ff:95:49:6e", KeyFingerprint.md5(blob))
    }

    @Test
    fun `md5 Ed25519`() {
        val blob = loadPublicKeyBlob("ed25519_unencrypted.pub")
        assertEquals("da:45:f7:4c:3f:af:09:b9:b6:04:49:47:66:55:1c:b1", KeyFingerprint.md5(blob))
    }

    @Test
    fun `md5 ECDSA 256`() {
        val blob = loadPublicKeyBlob("ecdsa256_unencrypted.pub")
        assertEquals("93:8f:2e:de:48:09:a5:fe:cb:32:a0:89:02:5c:33:89", KeyFingerprint.md5(blob))
    }

    // Bubblebabble test

    @Test
    fun `bubblebabble starts and ends with x`() {
        val blob = loadPublicKeyBlob("rsa_unencrypted.pub")
        val result = KeyFingerprint.bubblebabble(blob)
        assertTrue(result.startsWith("x"))
        assertTrue(result.endsWith("x"))
    }

    @Test
    fun `bubblebabble contains only valid chars`() {
        val blob = loadPublicKeyBlob("ed25519_unencrypted.pub")
        val result = KeyFingerprint.bubblebabble(blob)
        val validChars = "abcdefghiklmnoprstuvxyz-".toSet()
        assertTrue(result.all { it in validChars }, "Unexpected char in: $result")
    }

    @Test
    fun `bubblebabble is deterministic`() {
        val blob = loadPublicKeyBlob("rsa_unencrypted.pub")
        assertEquals(KeyFingerprint.bubblebabble(blob), KeyFingerprint.bubblebabble(blob))
    }

    // Random art tests (golden values from ssh-keygen -lvf -E sha256)

    @Test
    fun `randomArt RSA 2048`() {
        val blob = loadPublicKeyBlob("rsa_unencrypted.pub")
        val expected = "" +
            "+---[RSA 2048]----+\n" +
            "|      . +        |\n" +
            "|       O . .     |\n" +
            "|      . O % .    |\n" +
            "|     . o @.Xo .  |\n" +
            "|      . S.==o+   |\n" +
            "|         +*.*    |\n" +
            "|        o.+*o.   |\n" +
            "|        E+.B..   |\n" +
            "|        .o=+*.   |\n" +
            "+----[SHA256]-----+"
        assertEquals(expected, KeyFingerprint.randomArt(blob, "RSA", 2048))
    }

    @Test
    fun `randomArt Ed25519 256`() {
        val blob = loadPublicKeyBlob("ed25519_unencrypted.pub")
        val expected = "" +
            "+--[ED25519 256]--+\n" +
            "|         + o     |\n" +
            "|        o *      |\n" +
            "|         + .     |\n" +
            "|        o..      |\n" +
            "|       +S      oo|\n" +
            "|      o+...  .B+E|\n" +
            "|       .o. . *+OB|\n" +
            "|       o. . .oX+O|\n" +
            "|        .. .o+oOB|\n" +
            "+----[SHA256]-----+"
        assertEquals(expected, KeyFingerprint.randomArt(blob, "ED25519", 256))
    }

    @Test
    fun `randomArt header format varies with key type length`() {
        val blob = loadPublicKeyBlob("ecdsa256_unencrypted.pub")
        val art = KeyFingerprint.randomArt(blob, "ECDSA", 256)
        val firstLine = art.lines().first()
        assertTrue(firstLine.startsWith("+"))
        assertTrue(firstLine.endsWith("+"))
        assertTrue(firstLine.contains("[ECDSA 256]"))
    }
}

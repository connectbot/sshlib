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

package org.connectbot.sshlib.crypto

import org.connectbot.sshlib.SshException
import java.security.KeyPair
import java.security.PublicKey
import java.security.interfaces.ECPublicKey

internal fun inferKeyType(publicKey: PublicKey): String = when (publicKey.algorithm) {
    "Ed25519" -> "ssh-ed25519"

    "Ed448" -> "ssh-ed448"

    "EdDSA" -> {
        if (publicKey.encoded.size <= 44) "ssh-ed25519" else "ssh-ed448"
    }

    "EC", "ECDSA" -> {
        val ecPub = publicKey as ECPublicKey
        when (ecPub.params.order.bitLength()) {
            256 -> "ecdsa-sha2-nistp256"
            384 -> "ecdsa-sha2-nistp384"
            521 -> "ecdsa-sha2-nistp521"
            else -> throw SshException("Unsupported EC curve with order bit length: ${ecPub.params.order.bitLength()}")
        }
    }

    "RSA" -> "ssh-rsa"

    else -> throw SshException("Unsupported key type: ${publicKey.algorithm}")
}

internal fun inferKeyType(keyPair: KeyPair): String = inferKeyType(keyPair.public)

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
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.*
import java.util.Base64

internal object PemKeyReader {

    private enum class PemType { RSA, EC, PKCS8 }

    private class PemStructure(
        val type: PemType,
        var data: ByteArray,
        var procType: List<String>?,
        var dekInfo: List<String>?
    )

    fun isEncrypted(text: String): Boolean {
        val ps = parsePem(text)
        return ps.procType != null && ps.procType!!.size == 2 && ps.procType!![1] == "ENCRYPTED"
    }

    fun read(text: String, passphrase: String?): SshPrivateKey {
        val ps = parsePem(text)

        if (ps.procType != null && ps.procType!!.size == 2 && ps.procType!![1] == "ENCRYPTED") {
            if (passphrase == null) {
                throw SshException("PEM is encrypted, but no passphrase was specified")
            }
            decryptPem(ps, passphrase.toByteArray(Charsets.ISO_8859_1))
        }

        return when (ps.type) {
            PemType.RSA -> readPkcs1Rsa(ps.data)
            PemType.EC -> readSec1Ec(ps.data)
            PemType.PKCS8 -> readPkcs8(ps.data)
        }
    }

    private fun parsePem(text: String): PemStructure {
        val lines = text.lines()
        var i = 0

        var type: PemType? = null
        var endMarker: String? = null
        while (i < lines.size) {
            val line = lines[i].trim()
            when {
                line.startsWith("-----BEGIN RSA PRIVATE KEY-----") -> {
                    type = PemType.RSA
                    endMarker = "-----END RSA PRIVATE KEY-----"
                }
                line.startsWith("-----BEGIN EC PRIVATE KEY-----") -> {
                    type = PemType.EC
                    endMarker = "-----END EC PRIVATE KEY-----"
                }
                line.startsWith("-----BEGIN PRIVATE KEY-----") -> {
                    type = PemType.PKCS8
                    endMarker = "-----END PRIVATE KEY-----"
                }
            }
            i++
            if (type != null) break
        }

        if (type == null) throw SshException("Invalid PEM: no recognized BEGIN marker found")

        var procType: List<String>? = null
        var dekInfo: List<String>? = null
        while (i < lines.size) {
            val line = lines[i].trim()
            val colonIdx = line.indexOf(':')
            if (colonIdx == -1) break

            val name = line.substring(0, colonIdx + 1)
            val value = line.substring(colonIdx + 1).trim()
            val values = value.split(",").map { it.trim() }

            when (name) {
                "Proc-Type:" -> procType = values
                "DEK-Info:" -> dekInfo = values
            }
            i++
        }

        val base64Builder = StringBuilder()
        while (i < lines.size) {
            val line = lines[i].trim()
            if (line.startsWith(endMarker!!)) break
            base64Builder.append(line)
            i++
        }

        val data = Base64.getDecoder().decode(base64Builder.toString())
        if (data.isEmpty()) throw SshException("Invalid PEM: no data")

        return PemStructure(type, data, procType, dekInfo)
    }

    private fun decryptPem(ps: PemStructure, password: ByteArray) {
        val dekInfo = ps.dekInfo
            ?: throw SshException("Broken PEM: no DEK-Info but encryption enabled")
        if (dekInfo.size != 2) {
            throw SshException("Broken PEM: DEK-Info is incomplete")
        }
        val algo = dekInfo[0]
        val salt = KeyDecryption.hexToByteArray(dekInfo[1])
        ps.data = KeyDecryption.decryptPem(ps.data, password, salt, algo)
        ps.procType = null
        ps.dekInfo = null
    }

    internal fun readPkcs1Rsa(data: ByteArray): SshPrivateKey {
        val reader = DerReader(data)
        return reader.readSequence { seq ->
            val version = seq.readInteger()
            if (version != BigInteger.ZERO && version != BigInteger.ONE) {
                throw SshException("Wrong version ($version) in RSA PRIVATE KEY")
            }

            val n = seq.readInteger()
            val e = seq.readInteger()
            val d = seq.readInteger()
            val p = seq.readInteger()
            val q = seq.readInteger()
            val dP = seq.readInteger()
            val dQ = seq.readInteger()
            val qInv = seq.readInteger()

            val privSpec = RSAPrivateCrtKeySpec(n, e, d, p, q, dP, dQ, qInv)
            val pubSpec = RSAPublicKeySpec(n, e)
            val kf = KeyFactory.getInstance("RSA")
            val keyPair = KeyPair(kf.generatePublic(pubSpec), kf.generatePrivate(privSpec))

            SshPrivateKey("ssh-rsa", keyPair, "rsa-sha2-512")
        }
    }

    internal fun readSec1Ec(data: ByteArray): SshPrivateKey {
        val reader = DerReader(data)
        return reader.readSequence { seq ->
            val version = seq.readInteger()
            if (version != BigInteger.ONE) {
                throw SshException("Wrong version ($version) in EC PRIVATE KEY")
            }

            val privateBytes = seq.readOctetString()

            var curveOid: ByteArray? = null
            var publicBytes: ByteArray? = null

            while (seq.hasRemaining()) {
                when (seq.peekTag()) {
                    0xA0 -> curveOid = seq.readContextTag(0) { it.readObjectIdentifier() }
                    0xA1 -> publicBytes = seq.readContextTag(1) { it.readBitString() }
                    else -> seq.skipTag()
                }
            }

            val oid = curveOid ?: throw SshException("EC key missing curve OID")
            val pubPoint = publicBytes ?: throw SshException("EC key missing public key")

            val (ecGenSpec, sshAlg) = oidToCurve(oid)
            val params = AlgorithmParameters.getInstance("EC")
            params.init(ecGenSpec)
            val paramSpec = params.getParameterSpec(ECParameterSpec::class.java)

            val point = EcdsaSignatureAlgorithm.decodeEcPoint(pubPoint, paramSpec)
            val privKeySpec = ECPrivateKeySpec(BigInteger(1, privateBytes), paramSpec)
            val pubKeySpec = ECPublicKeySpec(point, paramSpec)

            val kf = KeyFactory.getInstance("EC")
            val keyPair = KeyPair(kf.generatePublic(pubKeySpec), kf.generatePrivate(privKeySpec))
            SshPrivateKey(sshAlg, keyPair, sshAlg)
        }
    }

    private fun readPkcs8(data: ByteArray): SshPrivateKey {
        // Use JCA's built-in PKCS#8 parsing — try each algorithm
        try {
            val kf = KeyFactory.getInstance("Ed25519")
            val privKey = kf.generatePrivate(PKCS8EncodedKeySpec(data))
            val edPriv = privKey as java.security.interfaces.EdECPrivateKey
            val seed = edPriv.bytes.orElseThrow { SshException("Cannot extract Ed25519 seed") }
            val pubKey = ed25519PublicKeyFromSeed(seed)
            return SshPrivateKey("ssh-ed25519", KeyPair(pubKey, privKey), "ssh-ed25519")
        } catch (_: InvalidKeySpecException) {}

        try {
            val kf = KeyFactory.getInstance("EC")
            val privKey = kf.generatePrivate(PKCS8EncodedKeySpec(data)) as java.security.interfaces.ECPrivateKey
            val fieldSize = (privKey.params.order.bitLength() + 7) / 8
            val sshAlg = when (fieldSize) {
                32 -> "ecdsa-sha2-nistp256"
                48 -> "ecdsa-sha2-nistp384"
                66 -> "ecdsa-sha2-nistp521"
                else -> throw SshException("Unknown EC key size: $fieldSize")
            }
            val pubKey = ecPublicKeyFromPkcs8(privKey)
            return SshPrivateKey(sshAlg, KeyPair(pubKey, privKey), sshAlg)
        } catch (_: InvalidKeySpecException) {}

        try {
            val kf = KeyFactory.getInstance("RSA")
            val privKey = kf.generatePrivate(PKCS8EncodedKeySpec(data)) as java.security.interfaces.RSAPrivateCrtKey
            val pubSpec = RSAPublicKeySpec(privKey.modulus, privKey.publicExponent)
            val pubKey = kf.generatePublic(pubSpec)
            return SshPrivateKey("ssh-rsa", KeyPair(pubKey, privKey), "rsa-sha2-512")
        } catch (_: InvalidKeySpecException) {}

        throw SshException("Unable to parse PKCS#8 key: unsupported algorithm")
    }

    internal fun ed25519PublicKeyFromSeed(seed: ByteArray): java.security.PublicKey {
        // Build PKCS#8 from seed, create private key, then use KPG with deterministic random
        val pkcs8 = encodeDer {
            sequence {
                integer(BigInteger.ZERO)
                sequence {
                    objectIdentifier(byteArrayOf(0x2b, 0x65, 0x70)) // Ed25519
                }
                octetString(encodeDer { octetString(seed) })
            }
        }
        val privKey = KeyFactory.getInstance("Ed25519")
            .generatePrivate(PKCS8EncodedKeySpec(pkcs8))

        // Use a deterministic SecureRandom that returns our seed
        val deterministicRandom = object : java.security.SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                System.arraycopy(seed, 0, bytes, 0, minOf(seed.size, bytes.size))
            }
        }
        val kpg = java.security.KeyPairGenerator.getInstance("Ed25519")
        kpg.initialize(NamedParameterSpec.ED25519, deterministicRandom)
        return kpg.generateKeyPair().public
    }

    private fun ecPublicKeyFromPkcs8(privKey: java.security.interfaces.ECPrivateKey): java.security.PublicKey {
        // Parse the PKCS#8 encoding to extract the embedded public key
        val encoded = privKey.encoded
        val reader = DerReader(encoded)
        return reader.readSequence { outer ->
            outer.readInteger() // version
            outer.readSequence { algId -> while (algId.hasRemaining()) algId.skipTag() }
            val innerBytes = outer.readOctetString()

            val innerReader = DerReader(innerBytes)
            innerReader.readSequence { seq ->
                seq.readInteger() // version
                seq.readOctetString() // private key bytes

                while (seq.hasRemaining()) {
                    when (seq.peekTag()) {
                        0xA1 -> {
                            val pubPoint = seq.readContextTag(1) { it.readBitString() }
                            val pubKeySpec = ECPublicKeySpec(
                                EcdsaSignatureAlgorithm.decodeEcPoint(pubPoint, privKey.params),
                                privKey.params
                            )
                            return@readSequence KeyFactory.getInstance("EC").generatePublic(pubKeySpec)
                        }
                        else -> seq.skipTag()
                    }
                }
                throw SshException("EC PKCS#8 key missing embedded public key")
            }
        }
    }

    internal fun oidToCurve(oid: ByteArray): Pair<ECGenParameterSpec, String> {
        return when {
            oid.contentEquals(SECP256R1_OID) ->
                ECGenParameterSpec("secp256r1") to "ecdsa-sha2-nistp256"
            oid.contentEquals(SECP384R1_OID) ->
                ECGenParameterSpec("secp384r1") to "ecdsa-sha2-nistp384"
            oid.contentEquals(SECP521R1_OID) ->
                ECGenParameterSpec("secp521r1") to "ecdsa-sha2-nistp521"
            else -> throw SshException("Unknown EC curve OID")
        }
    }

    internal val SECP256R1_OID = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07)
    internal val SECP384R1_OID = byteArrayOf(0x2b, 0x81.toByte(), 0x04, 0x00, 0x22)
    internal val SECP521R1_OID = byteArrayOf(0x2b, 0x81.toByte(), 0x04, 0x00, 0x23)
}

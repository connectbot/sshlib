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

sealed interface EncryptionInstance {
    data class Cipher(val cipher: PacketCipher) : EncryptionInstance
    data class Aead(val aead: PacketAead) : EncryptionInstance
}

enum class CipherEntry(
    val sshName: String,
    val keyLength: Int,
    val ivLength: Int,
    val blockSize: Int,
    val isAead: Boolean,
    private val factory: (key: ByteArray, iv: ByteArray, forEncryption: Boolean) -> EncryptionInstance
) {
    AES128_GCM(
        "aes128-gcm@openssh.com", 16, 12, 16, true,
        { key, iv, _ -> EncryptionInstance.Aead(AesGcmCipher(key, iv)) }
    ),
    AES256_GCM(
        "aes256-gcm@openssh.com", 32, 12, 16, true,
        { key, iv, _ -> EncryptionInstance.Aead(AesGcmCipher(key, iv)) }
    ),
    AES128_CTR(
        "aes128-ctr", 16, 16, 16, false,
        { key, iv, enc -> EncryptionInstance.Cipher(AesCtrCipher(key, iv, enc)) }
    ),
    AES256_CTR(
        "aes256-ctr", 32, 16, 16, false,
        { key, iv, enc -> EncryptionInstance.Cipher(AesCtrCipher(key, iv, enc)) }
    ),
    AES128_CBC(
        "aes128-cbc", 16, 16, 16, false,
        { key, iv, enc -> EncryptionInstance.Cipher(AesCbcCipher(key, iv, enc)) }
    ),
    AES256_CBC(
        "aes256-cbc", 32, 16, 16, false,
        { key, iv, enc -> EncryptionInstance.Cipher(AesCbcCipher(key, iv, enc)) }
    ),
    TRIPLE_DES_CBC(
        "3des-cbc", 24, 8, 8, false,
        { key, iv, enc -> EncryptionInstance.Cipher(TripleDesCbcCipher(key, iv, enc)) }
    );

    fun create(key: ByteArray, iv: ByteArray, forEncryption: Boolean): EncryptionInstance =
        factory(key, iv, forEncryption)

    companion object {
        val defaults: List<CipherEntry> = entries.toList()

        val defaultString: String = defaults.joinToString(",") { it.sshName }

        fun fromSshName(name: String): CipherEntry? =
            entries.firstOrNull { it.sshName == name }
    }
}

enum class MacEntry(
    val sshName: String,
    val keyLength: Int,
    val macLength: Int,
    val isEtm: Boolean,
    private val factory: (key: ByteArray) -> PacketMac
) {
    HMAC_SHA2_256_ETM(
        "hmac-sha2-256-etm@openssh.com", 32, 32, true,
        { key -> HmacSha256(key.copyOf(32)) }
    ),
    HMAC_SHA2_512_ETM(
        "hmac-sha2-512-etm@openssh.com", 64, 64, true,
        { key -> HmacSha512(key.copyOf(64)) }
    ),
    HMAC_SHA2_256(
        "hmac-sha2-256", 32, 32, false,
        { key -> HmacSha256(key.copyOf(32)) }
    ),
    HMAC_SHA2_512(
        "hmac-sha2-512", 64, 64, false,
        { key -> HmacSha512(key.copyOf(64)) }
    ),
    HMAC_SHA1_ETM(
        "hmac-sha1-etm@openssh.com", 20, 20, true,
        { key -> HmacSha1(key.copyOf(20)) }
    ),
    HMAC_SHA1(
        "hmac-sha1", 20, 20, false,
        { key -> HmacSha1(key.copyOf(20)) }
    );

    fun create(key: ByteArray): PacketMac = factory(key)

    companion object {
        val defaults: List<MacEntry> = entries.toList()

        val defaultString: String = defaults.joinToString(",") { it.sshName }

        fun fromSshName(name: String): MacEntry? =
            entries.firstOrNull { it.sshName == name }
    }
}

enum class KexType { DH, ECDH }

enum class KexEntry(
    val sshName: String,
    val hashAlgorithm: String,
    val type: KexType,
    private val factory: () -> KexAlgorithm
) {
    ECDH_SHA2_NISTP256(
        "ecdh-sha2-nistp256", "SHA-256", KexType.ECDH,
        { EcdhKeyExchange("nistp256") }
    ),
    ECDH_SHA2_NISTP384(
        "ecdh-sha2-nistp384", "SHA-384", KexType.ECDH,
        { EcdhKeyExchange("nistp384") }
    ),
    ECDH_SHA2_NISTP521(
        "ecdh-sha2-nistp521", "SHA-512", KexType.ECDH,
        { EcdhKeyExchange("nistp521") }
    ),
    DH_GROUP14_SHA256(
        "diffie-hellman-group14-sha256", "SHA-256", KexType.DH,
        { DiffieHellman("SHA-256") }
    ),
    DH_GROUP14_SHA1(
        "diffie-hellman-group14-sha1", "SHA-1", KexType.DH,
        { DiffieHellman("SHA-1") }
    );

    fun create(): KexAlgorithm = factory()

    companion object {
        val defaults: List<KexEntry> = entries.toList()

        val defaultString: String =
            defaults.joinToString(",") { it.sshName } + ",kex-strict-c-v00@openssh.com"

        fun fromSshName(name: String): KexEntry? =
            entries.firstOrNull { it.sshName == name }
    }
}

enum class SignatureEntry(
    val sshName: String,
    val algorithm: SshSignatureAlgorithm
) {
    SSH_ED25519("ssh-ed25519", Ed25519SignatureAlgorithm),
    SSH_ED448("ssh-ed448", Ed448SignatureAlgorithm),
    ECDSA_SHA2_NISTP256("ecdsa-sha2-nistp256", EcdsaSignatureAlgorithm),
    ECDSA_SHA2_NISTP384("ecdsa-sha2-nistp384", EcdsaSignatureAlgorithm),
    ECDSA_SHA2_NISTP521("ecdsa-sha2-nistp521", EcdsaSignatureAlgorithm),
    RSA_SHA2_256("rsa-sha2-256", RsaSignatureAlgorithm),
    RSA_SHA2_512("rsa-sha2-512", RsaSignatureAlgorithm),
    SSH_RSA("ssh-rsa", RsaSignatureAlgorithm);

    companion object {
        val defaults: List<SignatureEntry> = entries.toList()

        val defaultString: String = defaults.joinToString(",") { it.sshName }

        fun fromSshName(name: String): SignatureEntry? =
            entries.firstOrNull { it.sshName == name }
    }
}

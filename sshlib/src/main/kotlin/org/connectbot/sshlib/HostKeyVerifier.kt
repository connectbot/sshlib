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

package org.connectbot.sshlib

import org.connectbot.sshlib.crypto.Base64Compat
import java.io.File

/**
 * Verifies the identity of a server by checking its host key.
 *
 * Implementations of this interface determine whether a server's host key
 * is trusted. This is typically done by consulting a `known_hosts` database.
 */
interface HostKeyVerifier {
    /**
     * Verify the server's host key.
     *
     * @param key The server's public key.
     * @return true if the key is trusted, false otherwise.
     */
    suspend fun verify(key: PublicKey): Boolean

    suspend fun addKeys(keys: List<PublicKey>) {}
    suspend fun removeKeys(keys: List<PublicKey>) {}
}

/**
 * A generic public key representation.
 *
 * @param type The key type (e.g., "ssh-rsa", "ecdsa-sha2-nistp256").
 * @param encoded The raw key data (wire format).
 */
data class PublicKey(
    val type: String,
    val encoded: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as PublicKey
        if (type != other.type) return false
        if (!encoded.contentEquals(other.encoded)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + encoded.contentHashCode()
        return result
    }
}

/**
 * A host key verifier that reads from an OpenSSH-style `known_hosts` file.
 *
 * Currently supports:
 * - Plain hostnames (no hashed hosts yet)
 * - Wildcards (* and ?) in hostnames
 * - Multiple keys per host
 *
 * @param file The `known_hosts` file to read.
 */
class KnownHostsVerifier(
    private val file: File,
    private val hostname: String,
    private val port: Int = 22,
) : HostKeyVerifier {

    private val hostAlias: String = if (port == 22) hostname else "[$hostname]:$port"

    private val entries: List<Entry> by lazy {
        if (!file.exists()) return@lazy emptyList()
        file.readLines().mapNotNull { parseLine(it) }
    }

    override suspend fun verify(key: PublicKey): Boolean {
        val matchingEntries = entries.filter { entry ->
            entry.hosts.any { pattern -> matchHost(pattern, hostAlias) }
        }

        if (matchingEntries.isEmpty()) {
            return false // Unknown host
        }

        return matchingEntries.any { it.key == key }
    }

    private fun matchHost(pattern: String, hostname: String): Boolean {
        // TODO: Support hashed hosts (|1|salt|hash)
        if (pattern.startsWith("|1|")) return false

        // Simple wildcard matching
        // Note: Java Regex or simple manual matching.
        // Keeping it simple: exact match or basic wildcard
        if (pattern.contains("*") || pattern.contains("?")) {
            val regex = pattern
                .replace(".", "\\.")
                .replace("*", ".*")
                .replace("?", ".")
            return hostname.matches(regex.toRegex())
        }
        return pattern == hostname
    }

    private fun parseLine(line: String): Entry? {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return null

        val parts = trimmed.split(Regex("\\s+"))
        if (parts.size < 3) return null

        // Format: hostnames algorithm key [comment]
        val hosts = parts[0].split(",")
        val algorithm = parts[1]
        val keyData = try {
            Base64Compat.decode(parts[2])
        } catch (e: IllegalArgumentException) {
            return null
        }

        return Entry(hosts, PublicKey(algorithm, keyData))
    }

    private data class Entry(
        val hosts: List<String>,
        val key: PublicKey,
    )
}

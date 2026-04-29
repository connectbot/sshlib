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

/**
 * A host key specification used in destination constraints.
 *
 * @param keyBlob Wire-format public key blob
 * @param isCa True if this is a CA key that signed the destination's host certificate
 */
data class AgentKeySpec(
    val keyBlob: ByteArray,
    val isCa: Boolean,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as AgentKeySpec
        if (!keyBlob.contentEquals(other.keyBlob)) return false
        if (isCa != other.isCa) return false
        return true
    }

    override fun hashCode(): Int {
        var result = keyBlob.contentHashCode()
        result = 31 * result + isCa.hashCode()
        return result
    }
}

/**
 * One hop entry in a destination constraint for a key in the agent.
 *
 * Describes a single permitted (from → to) hop in a forwarding chain.
 * When [fromHostname] and [fromKeyspecs] are empty this is an origin-direct constraint
 * (key may be used directly from the machine running the agent).
 *
 * @param fromHostname Hostname of the previous hop, empty string for the origin machine
 * @param fromKeyspecs Host key specs of the previous hop, empty for the origin machine
 * @param toUsername Permitted destination username; empty string means any user is allowed
 * @param toHostname Destination hostname
 * @param toHostspecs Destination host key specs (must be non-empty)
 */
data class DestinationConstraint(
    val fromHostname: String,
    val fromKeyspecs: List<AgentKeySpec>,
    val toUsername: String,
    val toHostname: String,
    val toHostspecs: List<AgentKeySpec>,
)

/**
 * Provider interface for SSH agent forwarding.
 *
 * Implement this interface to handle agent requests from remote servers
 * when agent forwarding is enabled. The library will call these methods
 * when a remote server requests identities or signatures.
 */
interface AgentProvider {
    /**
     * Return the list of identities available for forwarding.
     *
     * Called when a remote server requests the list of available keys.
     */
    suspend fun getIdentities(): List<AgentIdentity>

    /**
     * Sign data with the specified key.
     *
     * Called when a remote server requests a signature. The provider should:
     * 1. Verify the request is legitimate (check context)
     * 2. Optionally prompt the user for approval
     * 3. Return the signature, or null to deny the request
     *
     * @param context Rich context about the signing request
     * @return SSH-encoded signature blob, or null to refuse
     */
    suspend fun signData(context: AgentSigningContext): ByteArray?
}

/**
 * A public key identity available in the agent.
 *
 * @param publicKeyBlob Wire-format public key blob
 * @param comment Human-readable comment describing the key
 * @param destinationConstraints Optional per-hop destination constraints; null means unconstrained
 */
data class AgentIdentity(
    val publicKeyBlob: ByteArray,
    val comment: String,
    val destinationConstraints: List<DestinationConstraint>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as AgentIdentity
        if (!publicKeyBlob.contentEquals(other.publicKeyBlob)) return false
        if (comment != other.comment) return false
        if (destinationConstraints != other.destinationConstraints) return false
        return true
    }

    override fun hashCode(): Int {
        var result = publicKeyBlob.contentHashCode()
        result = 31 * result + comment.hashCode()
        result = 31 * result + destinationConstraints.hashCode()
        return result
    }
}

/**
 * Context for agent signing decisions.
 *
 * Provides information to help the agent provider make informed security
 * decisions about whether to approve a signing request from a remote server.
 */
data class AgentSigningContext(
    /** Wire-format public key blob being requested */
    val publicKeyBlob: ByteArray,

    /** Data to be signed */
    val dataToSign: ByteArray,

    /** Signature flags (0 for default, or RSA_SHA2_256/512) */
    val flags: Int,

    /** Session ID from the SSH connection (for session binding) */
    val sessionId: ByteArray,

    /** Server's host key from key exchange */
    val serverHostKey: ByteArray,

    /** Whether session-bind extension was used */
    val isBound: Boolean,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as AgentSigningContext
        if (!publicKeyBlob.contentEquals(other.publicKeyBlob)) return false
        if (!dataToSign.contentEquals(other.dataToSign)) return false
        if (flags != other.flags) return false
        if (!sessionId.contentEquals(other.sessionId)) return false
        if (!serverHostKey.contentEquals(other.serverHostKey)) return false
        if (isBound != other.isBound) return false
        return true
    }

    override fun hashCode(): Int {
        var result = publicKeyBlob.contentHashCode()
        result = 31 * result + dataToSign.contentHashCode()
        result = 31 * result + flags
        result = 31 * result + sessionId.contentHashCode()
        result = 31 * result + serverHostKey.contentHashCode()
        result = 31 * result + isBound.hashCode()
        return result
    }
}

/**
 * Signature flags for agent sign requests.
 */
object AgentSignatureFlags {
    /** Request rsa-sha2-256 signature (for ssh-rsa keys) */
    const val RSA_SHA2_256 = 0x02

    /** Request rsa-sha2-512 signature (for ssh-rsa keys) */
    const val RSA_SHA2_512 = 0x04
}

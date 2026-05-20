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

package org.connectbot.sshlib.example

import org.connectbot.sshlib.HostKeyVerifier
import org.connectbot.sshlib.KnownHostsVerifier
import org.connectbot.sshlib.PublicKey
import java.io.File
import java.security.MessageDigest
import java.util.Base64

internal class InteractiveHostKeyVerifier(
    private val hostname: String,
    private val port: Int,
) : HostKeyVerifier {
    private val knownHostsFile = File(System.getProperty("user.home"), ".ssh/known_hosts")
    private val delegate = KnownHostsVerifier(knownHostsFile, hostname, port)

    override suspend fun verify(key: PublicKey): Boolean {
        if (delegate.verify(key)) return true
        printFingerprint(key)
        if (readlnOrNull()?.trim()?.lowercase() != "yes") return false
        appendToKnownHosts(key)
        System.err.println("Warning: Permanently added '$hostname' to the list of known hosts.")
        return true
    }

    private fun printFingerprint(key: PublicKey) {
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(key.encoded)
        val fingerprintStr = Base64.getEncoder().encodeToString(fingerprint).trimEnd('=')
        System.err.println("The authenticity of host '$hostname ($hostname)' can't be established.")
        System.err.println("${key.type} key fingerprint is SHA256:$fingerprintStr.")
        System.err.print("Are you sure you want to continue connecting (yes/no)? ")
        System.err.flush()
    }

    private fun appendToKnownHosts(key: PublicKey) {
        val hostEntry = if (port == 22) hostname else "[$hostname]:$port"
        val keyBase64 = Base64.getEncoder().encodeToString(key.encoded)
        knownHostsFile.parentFile?.mkdirs()
        knownHostsFile.appendText("$hostEntry ${key.type} $keyBase64\n")
    }
}

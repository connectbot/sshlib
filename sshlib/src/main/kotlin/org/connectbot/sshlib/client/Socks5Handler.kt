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

package org.connectbot.sshlib.client

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeByte
import io.ktor.utils.io.writeFully
import org.connectbot.sshlib.Socks5Authenticator
import org.slf4j.LoggerFactory

/**
 * SOCKS5 protocol handler (RFC 1928 + RFC 1929).
 *
 * Handles the SOCKS5 handshake on an accepted TCP connection to determine
 * the target host and port for dynamic port forwarding.
 */
internal class Socks5Handler(
    private val authenticator: Socks5Authenticator? = null,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(Socks5Handler::class.java)

        const val SOCKS5_VERSION: Byte = 0x05
        const val AUTH_NONE: Byte = 0x00
        const val AUTH_USERNAME_PASSWORD: Byte = 0x02
        const val AUTH_NO_ACCEPTABLE: Byte = 0xFF.toByte()
        const val CMD_CONNECT: Byte = 0x01
        const val ATYP_IPV4: Byte = 0x01
        const val ATYP_DOMAIN: Byte = 0x03
        const val ATYP_IPV6: Byte = 0x04
        const val REPLY_SUCCESS: Byte = 0x00
        const val REPLY_GENERAL_FAILURE: Byte = 0x01
        const val REPLY_NOT_ALLOWED: Byte = 0x02
        const val REPLY_COMMAND_NOT_SUPPORTED: Byte = 0x07
        const val REPLY_ADDRESS_TYPE_NOT_SUPPORTED: Byte = 0x08
    }

    data class ConnectRequest(val host: String, val port: Int)

    suspend fun handleHandshake(read: ByteReadChannel, write: ByteWriteChannel): ConnectRequest? {
        // Phase 1: Method selection
        val version = read.readByte()
        if (version != SOCKS5_VERSION) {
            logger.warn("Unsupported SOCKS version: $version")
            return null
        }

        val numMethods = read.readByte().toInt() and 0xFF
        if (numMethods == 0) {
            logger.warn("No auth methods offered")
            return null
        }

        val methods = ByteArray(numMethods)
        read.readFully(methods, 0, numMethods)

        val selectedMethod = selectAuthMethod(methods)
        write.writeByte(SOCKS5_VERSION)
        write.writeByte(selectedMethod)
        write.flush()

        if (selectedMethod == AUTH_NO_ACCEPTABLE) {
            logger.warn("No acceptable auth method")
            return null
        }

        // Phase 2: Authentication (if username/password)
        if (selectedMethod == AUTH_USERNAME_PASSWORD) {
            if (!handleUsernamePasswordAuth(read, write)) {
                return null
            }
        }

        // Phase 3: Connect request
        return handleConnectRequest(read, write)
    }

    private fun selectAuthMethod(methods: ByteArray): Byte {
        if (authenticator != null) {
            if (AUTH_USERNAME_PASSWORD in methods) return AUTH_USERNAME_PASSWORD
        } else {
            if (AUTH_NONE in methods) return AUTH_NONE
        }
        return AUTH_NO_ACCEPTABLE
    }

    private suspend fun handleUsernamePasswordAuth(
        read: ByteReadChannel,
        write: ByteWriteChannel,
    ): Boolean {
        val authVersion = read.readByte()
        if (authVersion != 0x01.toByte()) {
            logger.warn("Unsupported auth sub-negotiation version: $authVersion")
            write.writeByte(0x01)
            write.writeByte(0x01) // failure
            write.flush()
            return false
        }

        val usernameLen = read.readByte().toInt() and 0xFF
        val usernameBytes = ByteArray(usernameLen)
        read.readFully(usernameBytes, 0, usernameLen)
        val username = String(usernameBytes, Charsets.UTF_8)

        val passwordLen = read.readByte().toInt() and 0xFF
        val passwordBytes = ByteArray(passwordLen)
        read.readFully(passwordBytes, 0, passwordLen)
        val password = String(passwordBytes, Charsets.UTF_8)

        val auth = authenticator ?: return false
        val success = auth.authenticate(username, password)

        write.writeByte(0x01) // auth version
        write.writeByte(if (success) 0x00 else 0x01)
        write.flush()

        if (!success) {
            logger.warn("SOCKS5 authentication failed for user: $username")
        }
        return success
    }

    private suspend fun handleConnectRequest(
        read: ByteReadChannel,
        write: ByteWriteChannel,
    ): ConnectRequest? {
        val ver = read.readByte()
        if (ver != SOCKS5_VERSION) {
            logger.warn("Unexpected version in request: $ver")
            return null
        }

        val cmd = read.readByte()
        read.readByte() // RSV

        if (cmd != CMD_CONNECT) {
            logger.warn("Unsupported SOCKS5 command: $cmd")
            sendReply(write, REPLY_COMMAND_NOT_SUPPORTED)
            return null
        }

        val atyp = read.readByte()
        val host: String = when (atyp) {
            ATYP_IPV4 -> {
                val addr = ByteArray(4)
                read.readFully(addr, 0, 4)
                "${addr[0].toInt() and 0xFF}.${addr[1].toInt() and 0xFF}.${addr[2].toInt() and 0xFF}.${addr[3].toInt() and 0xFF}"
            }

            ATYP_DOMAIN -> {
                val domainLen = read.readByte().toInt() and 0xFF
                val domainBytes = ByteArray(domainLen)
                read.readFully(domainBytes, 0, domainLen)
                String(domainBytes, Charsets.US_ASCII)
            }

            ATYP_IPV6 -> {
                val addr = ByteArray(16)
                read.readFully(addr, 0, 16)
                buildString {
                    for (i in 0 until 16 step 2) {
                        if (i > 0) append(':')
                        append(String.format("%02x%02x", addr[i], addr[i + 1]))
                    }
                }
            }

            else -> {
                logger.warn("Unsupported address type: $atyp")
                sendReply(write, REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
                return null
            }
        }

        val portHi = read.readByte().toInt() and 0xFF
        val portLo = read.readByte().toInt() and 0xFF
        val port = (portHi shl 8) or portLo

        sendReply(write, REPLY_SUCCESS)
        return ConnectRequest(host, port)
    }

    private suspend fun sendReply(write: ByteWriteChannel, reply: Byte) {
        write.writeByte(SOCKS5_VERSION)
        write.writeByte(reply)
        write.writeByte(0x00) // RSV
        write.writeByte(ATYP_IPV4)
        write.writeFully(ByteArray(4), 0, 4) // BND.ADDR
        write.writeByte(0x00) // BND.PORT high
        write.writeByte(0x00) // BND.PORT low
        write.flush()
    }
}

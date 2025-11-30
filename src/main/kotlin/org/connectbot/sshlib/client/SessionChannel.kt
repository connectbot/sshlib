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

package org.connectbot.sshlib.client

import kotlinx.coroutines.runBlocking
import org.connectbot.sshlib.struct.*
import org.slf4j.LoggerFactory

/**
 * Represents an SSH session channel (RFC 4254 section 6).
 *
 * Session channels are used for interactive shells, command execution,
 * and subsystem invocation (like SFTP).
 *
 * @param connection The SSH connection managing this channel
 * @param localChannelNumber The local channel number
 * @param remoteChannelNumber The remote channel number assigned by server
 * @param maxPacketSize Maximum packet size for this channel
 */
class SessionChannel internal constructor(
    private val connection: SshConnection,
    val localChannelNumber: Int,
    private var remoteChannelNumber: Int,
    private val maxPacketSize: Int
) {
    companion object {
        private val logger = LoggerFactory.getLogger(SessionChannel::class.java)
    }

    private var _isOpen = true

    val isOpen: Boolean
        get() = _isOpen

    /**
     * Request a PTY (pseudo-terminal) for this session (RFC 4254 section 6.2).
     *
     * @param terminalType Terminal type (e.g., "xterm", "vt100")
     * @param widthChars Terminal width in characters
     * @param heightRows Terminal height in rows
     * @param widthPixels Terminal width in pixels (usually 0)
     * @param heightPixels Terminal height in pixels (usually 0)
     * @param terminalModes Encoded terminal modes (empty for defaults)
     * @return true if PTY request was accepted
     */
    fun requestPty(
        terminalType: String = "xterm",
        widthChars: Int = 80,
        heightRows: Int = 24,
        widthPixels: Int = 0,
        heightPixels: Int = 0,
        terminalModes: ByteArray = byteArrayOf(0) // TTY_OP_END
    ): Boolean = runBlocking {
        logger.debug("Requesting PTY: $terminalType ${widthChars}x$heightRows")
        connection.sendChannelRequest(
            remoteChannelNumber,
            "pty-req",
            wantReply = true
        ) { msg ->
            val ptyReq = ChannelRequestPtyReq()

            val termBytes = ByteString()
            termBytes.setLenData(terminalType.length.toLong())
            termBytes.setData(terminalType.toByteArray(Charsets.US_ASCII))
            ptyReq.setTerm(termBytes)

            ptyReq.setTerminalWidth(widthChars.toLong())
            ptyReq.setTerminalHeight(heightRows.toLong())
            ptyReq.setTerminalWidthPixels(widthPixels.toLong())
            ptyReq.setTerminalHeightPixels(heightPixels.toLong())

            val modeString = ByteString()
            modeString.setLenData(terminalModes.size.toLong())
            modeString.setData(terminalModes)
            ptyReq.setTerminalModes(modeString)

            msg.setRequestSpecificFields(ptyReq)
        }
    }

    /**
     * Request a shell for this session (RFC 4254 section 6.5).
     *
     * @return true if shell request was accepted
     */
    fun requestShell(): Boolean = runBlocking {
        logger.debug("Requesting shell on channel $localChannelNumber")
        connection.sendChannelRequest(
            remoteChannelNumber,
            "shell",
            wantReply = true
        ) { msg ->
            val shellReq = ChannelRequestShell()
            shellReq._check()
            msg.setRequestSpecificFields(shellReq)
        }
    }

    /**
     * Close this channel (RFC 4254 section 5.3).
     */
    fun close() = runBlocking {
        if (!_isOpen) {
            logger.debug("Channel $localChannelNumber already closed")
            return@runBlocking
        }

        logger.debug("Closing channel $localChannelNumber")
        connection.sendChannelClose(remoteChannelNumber)
        _isOpen = false
    }
}

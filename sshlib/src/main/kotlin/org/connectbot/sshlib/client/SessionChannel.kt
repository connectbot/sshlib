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
import org.connectbot.sshlib.SshSession
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
    override val localChannelNumber: Int,
    private var _remoteChannelNumber: Int,
    private val maxPacketSize: Int
) : SshSession {
    companion object {
        private val logger = LoggerFactory.getLogger(SessionChannel::class.java)
    }

    private var _isOpen = true

    override val isOpen: Boolean
        get() = _isOpen

    override val remoteChannelNumber: Int
        get() = _remoteChannelNumber

    override suspend fun requestPty(
        terminalType: String,
        widthChars: Int,
        heightRows: Int,
        widthPixels: Int,
        heightPixels: Int,
        terminalModes: ByteArray
    ): Boolean {
        logger.debug("Requesting PTY: $terminalType ${widthChars}x$heightRows")
        return connection.sendChannelRequest(
            _remoteChannelNumber,
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

    override suspend fun requestShell(): Boolean {
        logger.debug("Requesting shell on channel $localChannelNumber")
        return connection.sendChannelRequest(
            _remoteChannelNumber,
            "shell",
            wantReply = true
        ) { msg ->
            val shellReq = ChannelRequestShell()
            shellReq._check()
            msg.setRequestSpecificFields(shellReq)
        }
    }

    override fun close() {
        if (!_isOpen) {
            logger.debug("Channel $localChannelNumber already closed")
            return
        }

        logger.debug("Closing channel $localChannelNumber")
        runBlocking {
            connection.sendChannelClose(_remoteChannelNumber)
        }
        _isOpen = false
    }
}

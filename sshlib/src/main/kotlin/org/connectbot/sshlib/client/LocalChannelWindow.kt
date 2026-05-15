/*
 * ConnectBot SSH Library
 * Copyright 2025-2026 Kenny Root
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

import org.connectbot.sshlib.SshException

/**
 * Tracks SSH channel flow control windows per RFC 4254 §5.2.
 *
 * Local window: bytes we are willing to receive. Enforces that the server never
 * exceeds it; auto-refills when below [adjustThreshold].
 *
 * Remote window: bytes the server is willing to receive. Enforces uint32 max
 * and positive-only adjustments per the protocol.
 */
internal class LocalChannelWindow(
    private val initialSize: Int,
    private val adjustThreshold: Int = 16 * 1024,
    remoteInitial: Long = 0,
) {
    companion object {
        const val MAX_WINDOW_SIZE = 0xFFFFFFFFL
    }

    private var localRemaining: Long = initialSize.toLong()

    @Volatile var remoteRemaining: Long = remoteInitial
        private set

    /**
     * Consume [size] bytes from the local window, rejecting excess data.
     * Returns the window-adjust amount to send back (0 if no adjust needed).
     */
    fun consumeLocal(size: Int): Int {
        if (size > localRemaining) {
            throw SshException("Server sent $size bytes exceeding local window ($localRemaining)")
        }
        localRemaining -= size
        return if (localRemaining < adjustThreshold) {
            val adjust = initialSize - localRemaining.toInt()
            localRemaining += adjust
            adjust
        } else {
            0
        }
    }

    /**
     * Apply a window adjustment from the server, increasing the remote window.
     * Validates [bytesToAdd] is positive and won't overflow the uint32 max.
     */
    fun adjustRemote(bytesToAdd: Long) {
        if (bytesToAdd <= 0) {
            throw SshException("Invalid window adjust: bytesToAdd must be positive, got $bytesToAdd")
        }
        if (remoteRemaining + bytesToAdd > MAX_WINDOW_SIZE) {
            throw SshException("Channel window overflow: current=$remoteRemaining, adding=$bytesToAdd exceeds max $MAX_WINDOW_SIZE")
        }
        remoteRemaining += bytesToAdd
    }

    /**
     * Consume [size] bytes from the remote window for sending.
     * Caller must ensure [remoteRemaining] > 0 before calling.
     */
    fun consumeRemote(size: Int) {
        remoteRemaining -= size
    }
}

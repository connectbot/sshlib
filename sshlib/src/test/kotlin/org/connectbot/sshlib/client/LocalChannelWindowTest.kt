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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import kotlin.test.assertFailsWith

class LocalChannelWindowTest {

    @Test
    fun `consumeLocal rejects data exceeding window`() {
        val w = LocalChannelWindow(initialSize = 1024, adjustThreshold = 0)
        assertFailsWith<SshException> { w.consumeLocal(1025) }
    }

    @Test
    fun `consumeLocal accepts data exactly filling window`() {
        val w = LocalChannelWindow(initialSize = 1024, adjustThreshold = 0)
        val adjust = w.consumeLocal(1024)
        assertEquals(0, adjust)
    }

    @Test
    fun `consumeLocal returns adjust when below threshold`() {
        val w = LocalChannelWindow(initialSize = 1024, adjustThreshold = 512)
        val adjust = w.consumeLocal(600)
        assertEquals(1024 - (1024 - 600), adjust)
    }

    @Test
    fun `consumeLocal returns 0 when above threshold`() {
        val w = LocalChannelWindow(initialSize = 1024, adjustThreshold = 64)
        val adjust = w.consumeLocal(100)
        assertEquals(0, adjust)
    }

    @Test
    fun `adjustRemote rejects zero`() {
        val w = LocalChannelWindow(initialSize = 1024)
        assertFailsWith<SshException> { w.adjustRemote(0) }
    }

    @Test
    fun `adjustRemote rejects negative`() {
        val w = LocalChannelWindow(initialSize = 1024)
        assertFailsWith<SshException> { w.adjustRemote(-1) }
    }

    @Test
    fun `adjustRemote rejects overflow past uint32 max`() {
        val w = LocalChannelWindow(initialSize = 1024, remoteInitial = 64 * 1024L)
        val overflow = LocalChannelWindow.MAX_WINDOW_SIZE - 64 * 1024L + 1L
        assertFailsWith<SshException> { w.adjustRemote(overflow) }
    }

    @Test
    fun `adjustRemote accepts value reaching exactly uint32 max`() {
        val w = LocalChannelWindow(initialSize = 1024, remoteInitial = 64 * 1024L)
        val maxAdd = LocalChannelWindow.MAX_WINDOW_SIZE - 64 * 1024L
        w.adjustRemote(maxAdd)
        assertEquals(LocalChannelWindow.MAX_WINDOW_SIZE, w.remoteRemaining)
    }

    @Test
    fun `consumeRemote decrements remote window`() {
        val w = LocalChannelWindow(initialSize = 1024, remoteInitial = 1000L)
        w.consumeRemote(300)
        assertEquals(700L, w.remoteRemaining)
    }
}

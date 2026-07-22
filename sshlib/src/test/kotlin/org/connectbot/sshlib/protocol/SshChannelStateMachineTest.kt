/*
 * ConnectBot SSH Library
 * Copyright 2026 Kenny Root
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

package org.connectbot.sshlib.protocol

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SshChannelStateMachineTest {
    @Test
    fun `every channel transition is explicit formal metadata`() {
        val model = SshChannelStateMachine(SshChannelState.OPEN).formalModel()

        assertEquals(SshChannelState.entries.toSet(), model.states)
        assertEquals(SshChannelTransitionId.entries.toSet(), model.transitions.map { it.id }.toSet())
    }

    @Test
    fun `opening accepts exactly one terminal response`() = runTest {
        val confirmed = SshChannelStateMachine(SshChannelState.OPENING)
        assertTrue(confirmed.openConfirmed())
        assertEquals(SshChannelState.OPEN, confirmed.state)
        assertFalse(confirmed.openFailed())

        val failed = SshChannelStateMachine(SshChannelState.OPENING)
        assertTrue(failed.openFailed())
        assertEquals(SshChannelState.CLOSED, failed.state)
        assertFalse(failed.openConfirmed())
    }

    @Test
    fun `EOF independently closes each data direction`() = runTest {
        val machine = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(machine.sendEof())
        assertEquals(SshChannelState.LOCAL_EOF, machine.state)
        assertFalse(machine.sendData())
        assertTrue(machine.receiveData())

        assertTrue(machine.receiveEof())
        assertEquals(SshChannelState.BOTH_EOF, machine.state)
        assertFalse(machine.sendData())
        assertFalse(machine.receiveData())
    }

    @Test
    fun `remote EOF still permits outbound data`() = runTest {
        val machine = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(machine.receiveEof())
        assertEquals(SshChannelState.REMOTE_EOF, machine.state)
        assertTrue(machine.sendData())
        assertFalse(machine.receiveData())
    }

    @Test
    fun `local close waits for remote close and blocks channel operations`() = runTest {
        val machine = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(machine.sendClose())
        assertEquals(SshChannelState.CLOSE_SENT, machine.state)
        assertFalse(machine.isOpen)
        assertFalse(machine.sendData())
        assertFalse(machine.receiveData())
        assertFalse(machine.sendEof())
        assertTrue(machine.receiveClose())
        assertEquals(SshChannelState.CLOSED, machine.state)
    }

    @Test
    fun `remote close is terminal and duplicate close is rejected`() = runTest {
        val machine = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(machine.receiveClose())
        assertEquals(SshChannelState.CLOSED, machine.state)
        assertFalse(machine.receiveClose())
        assertFalse(machine.sendClose())
    }

    @Test
    fun `disconnect closes opening and established channels`() = runTest {
        val opening = SshChannelStateMachine(SshChannelState.OPENING)
        val established = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(opening.disconnect())
        assertTrue(established.disconnect())
        assertEquals(SshChannelState.CLOSED, opening.state)
        assertEquals(SshChannelState.CLOSED, established.state)
    }
}

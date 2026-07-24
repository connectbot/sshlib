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
        val runtimeOperations = model.operations
            .filter { it.id in SshChannelTransitionId.entries.map(SshChannelTransitionId::name) }
            .associateBy { it.id }
        model.transitions.forEach { transition ->
            val operation = runtimeOperations.getValue(transition.id.name)
            assertEquals(transition.eventName, operation.eventName)
            assertEquals(transition.source.name, operation.sourceStateName)
            assertEquals(transition.target.name, operation.targetStateName)
            assertEquals(transition.effects, operation.effects)
            assertEquals(transition.origin, operation.origin)
            assertEquals(transition.scope, operation.scope)
            assertEquals(transition.requiresAuthenticatedConnection, operation.requiresAuthenticatedConnection)
        }
    }

    @Test
    fun `construction and rejection semantics are explicit formal operations`() {
        val model = SshChannelStateMachine(SshChannelState.OPEN).formalModel()
        val constructionIds = SshChannelConstructionId.entries.mapTo(mutableSetOf(), SshChannelConstructionId::name)
        val constructions = model.operations.filter { it.id in constructionIds }

        assertEquals(constructionIds, constructions.mapTo(mutableSetOf()) { it.id })
        assertTrue(constructions.all { it.sourceStateName == model.unallocatedStateName })
        assertEquals(
            SshChannelOperationScope.CONNECTION_TRANSITION,
            constructions.single { it.id == SshChannelConstructionId.ALLOCATE_LOCAL_OPEN.name }.scope,
        )
        assertEquals(
            SshChannelOperationScope.CHANNEL_ATTEMPT,
            constructions.single { it.id == SshChannelConstructionId.ACCEPT_REMOTE_OPEN.name }.scope,
        )
        assertTrue(constructions.all { it.requiresAuthenticatedConnection })
        assertTrue(model.rejectedOperationEffects.isEmpty())
    }

    @Test
    fun `disconnect is teardown rather than a malicious channel attempt`() {
        val model = SshChannelStateMachine(SshChannelState.OPEN).formalModel()
        val disconnects = model.operations.filter { it.eventId == SshChannelEventId.DISCONNECT }

        assertTrue(disconnects.isNotEmpty())
        assertTrue(disconnects.all { it.scope == SshChannelOperationScope.CONNECTION_TEARDOWN })
        assertTrue(disconnects.none { it.requiresAuthenticatedConnection })
        assertTrue(disconnects.all { it.origin == SshChannelEventOrigin.CONNECTION_CONTROL })
    }

    @Test
    fun `packet and local operations have distinct typed origins`() {
        val operations = SshChannelStateMachine(SshChannelState.OPEN).formalModel().operations
        val localEvents = setOf(
            SshChannelEventId.ALLOCATE_LOCAL_OPEN,
            SshChannelEventId.SEND_CLOSE,
            SshChannelEventId.SEND_DATA,
            SshChannelEventId.SEND_EOF,
            SshChannelEventId.SEND_REQUEST,
        )
        val packetEvents = SshChannelEventId.entries.toSet() - localEvents - SshChannelEventId.DISCONNECT

        assertTrue(operations.filter { it.eventId in packetEvents }.all { it.origin == SshChannelEventOrigin.PARSED_PACKET })
        assertTrue(operations.filter { it.eventId in localEvents }.all { it.origin == SshChannelEventOrigin.LOCAL_COMMAND })
    }

    @Test
    fun `only an accepted transition executes its effect callback`() = runTest {
        val machine = SshChannelStateMachine(SshChannelState.OPEN)
        var effects = 0

        assertTrue(machine.sendEof { effects++ })
        assertFalse(machine.sendEof { effects++ })
        assertFalse(machine.sendData { effects++ })

        assertEquals(1, effects)
    }

    @Test
    fun `accepted callback receives source-specific transition metadata`() = runTest {
        val remotelyClosed = SshChannelStateMachine(SshChannelState.OPEN)
        val closeSent = SshChannelStateMachine(SshChannelState.OPEN)
        var remoteCloseEffects = emptySet<SshChannelEffect>()
        var closeReplyEffects = emptySet<SshChannelEffect>()

        remotelyClosed.receiveClose { remoteCloseEffects = it.effects }
        closeSent.sendClose {}
        closeSent.receiveClose { closeReplyEffects = it.effects }

        assertTrue(SshChannelEffect.SEND_CLOSE in remoteCloseEffects)
        assertFalse(SshChannelEffect.SEND_CLOSE in closeReplyEffects)
        assertEquals(
            SshChannelEventOrigin.PARSED_PACKET,
            closeSent.formalModel().transitions.first {
                it.id == SshChannelTransitionId.RECEIVE_CLOSE_CLOSE_SENT
            }.origin,
        )
    }

    @Test
    fun `opening accepts exactly one terminal response`() = runTest {
        val confirmed = SshChannelStateMachine(SshChannelState.OPENING)
        assertTrue(confirmed.openConfirmed {})
        assertEquals(SshChannelState.OPEN, confirmed.state)
        assertFalse(confirmed.openFailed {})

        val failed = SshChannelStateMachine(SshChannelState.OPENING)
        assertTrue(failed.openFailed {})
        assertEquals(SshChannelState.CLOSED, failed.state)
        assertFalse(failed.openConfirmed {})
    }

    @Test
    fun `EOF independently closes each data direction`() = runTest {
        val machine = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(machine.sendEof {})
        assertEquals(SshChannelState.LOCAL_EOF, machine.state)
        assertFalse(machine.sendData {})
        assertTrue(machine.receiveData {})

        assertTrue(machine.receiveEof {})
        assertEquals(SshChannelState.BOTH_EOF, machine.state)
        assertFalse(machine.sendData {})
        assertFalse(machine.receiveData {})
    }

    @Test
    fun `remote EOF still permits outbound data`() = runTest {
        val machine = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(machine.receiveEof {})
        assertEquals(SshChannelState.REMOTE_EOF, machine.state)
        assertTrue(machine.sendData {})
        assertFalse(machine.receiveData {})
    }

    @Test
    fun `local close waits for remote close and blocks channel operations`() = runTest {
        val machine = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(machine.sendClose {})
        assertEquals(SshChannelState.CLOSE_SENT, machine.state)
        assertFalse(machine.isOpen)
        assertFalse(machine.sendData {})
        assertTrue(machine.receiveData {})
        assertFalse(machine.sendEof {})
        assertTrue(machine.receiveClose {})
        assertEquals(SshChannelState.CLOSED, machine.state)
    }

    @Test
    fun `remote close is terminal and duplicate close is rejected`() = runTest {
        val machine = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(machine.receiveClose {})
        assertEquals(SshChannelState.CLOSED, machine.state)
        assertFalse(machine.receiveClose {})
        assertFalse(machine.sendClose {})
    }

    @Test
    fun `disconnect closes opening and established channels`() = runTest {
        val opening = SshChannelStateMachine(SshChannelState.OPENING)
        val established = SshChannelStateMachine(SshChannelState.OPEN)

        assertTrue(opening.disconnect {})
        assertTrue(established.disconnect {})
        assertEquals(SshChannelState.CLOSED, opening.state)
        assertEquals(SshChannelState.CLOSED, established.state)
    }
}

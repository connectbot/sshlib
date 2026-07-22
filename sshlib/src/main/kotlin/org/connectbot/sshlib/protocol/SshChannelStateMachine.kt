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

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import ru.nsk.kstatemachine.event.Event
import ru.nsk.kstatemachine.metainfo.MetaInfo
import ru.nsk.kstatemachine.state.IState
import ru.nsk.kstatemachine.state.State
import ru.nsk.kstatemachine.state.finalState
import ru.nsk.kstatemachine.state.initialState
import ru.nsk.kstatemachine.state.onEntry
import ru.nsk.kstatemachine.state.state
import ru.nsk.kstatemachine.state.transition
import ru.nsk.kstatemachine.statemachine.ProcessingResult
import ru.nsk.kstatemachine.statemachine.StateMachine
import ru.nsk.kstatemachine.statemachine.createStdLibStateMachine

/**
 * The protocol-visible lifecycle of one SSH connection-layer channel.
 *
 * EOF is directional. Sending EOF only closes the local-to-remote data direction, while receiving
 * EOF only closes the remote-to-local direction. CLOSE terminates both directions; after sending
 * CLOSE, the channel remains in [CLOSE_SENT] until the peer's CLOSE arrives or the connection is
 * disconnected.
 */
internal enum class SshChannelState {
    OPENING,
    OPEN,
    LOCAL_EOF,
    REMOTE_EOF,
    BOTH_EOF,
    CLOSE_SENT,
    CLOSED,
}

internal enum class SshChannelEffect {
    ADJUST_WINDOW,
    CLOSE_CHANNEL,
    CLOSE_INBOUND_STREAMS,
    COMPLETE_OPEN,
    DELIVER_DATA,
    DELIVER_REQUEST,
    FAIL_OPEN,
    SEND_CLOSE,
    SEND_DATA,
    SEND_EOF,
    SEND_OPEN,
    SEND_OPEN_CONFIRMATION,
    SEND_REQUEST,
}

internal enum class SshChannelConstructionId {
    ALLOCATE_LOCAL_OPEN,
    ACCEPT_REMOTE_OPEN,
}

internal enum class SshChannelEventId(
    val tlaName: String,
) {
    ACCEPT_REMOTE_OPEN("AcceptRemoteOpen"),
    ALLOCATE_LOCAL_OPEN("AllocateLocalOpen"),
    DISCONNECT("Disconnect"),
    OPEN_CONFIRMED("OpenConfirmed"),
    OPEN_FAILED("OpenFailed"),
    RECEIVE_CLOSE("ReceiveClose"),
    RECEIVE_DATA("ReceiveData"),
    RECEIVE_EOF("ReceiveEof"),
    RECEIVE_REQUEST("ReceiveRequest"),
    RECEIVE_WINDOW_ADJUST("ReceiveWindowAdjust"),
    SEND_CLOSE("SendClose"),
    SEND_DATA("SendData"),
    SEND_EOF("SendEof"),
    SEND_REQUEST("SendRequest"),
}

internal enum class SshChannelOperationScope {
    CHANNEL_ATTEMPT,
    CONNECTION_TRANSITION,
    CONNECTION_TEARDOWN,
}

/** Stable transition identifiers used by runtime tests and, later, TLA+ generation. */
internal enum class SshChannelTransitionId {
    OPEN_CONFIRMED,
    OPEN_FAILED,
    SEND_DATA_OPEN,
    SEND_DATA_REMOTE_EOF,
    RECEIVE_DATA_OPEN,
    RECEIVE_DATA_LOCAL_EOF,
    SEND_REQUEST_OPEN,
    SEND_REQUEST_LOCAL_EOF,
    SEND_REQUEST_REMOTE_EOF,
    SEND_REQUEST_BOTH_EOF,
    RECEIVE_REQUEST_OPEN,
    RECEIVE_REQUEST_LOCAL_EOF,
    RECEIVE_REQUEST_REMOTE_EOF,
    RECEIVE_REQUEST_BOTH_EOF,
    RECEIVE_WINDOW_ADJUST_OPEN,
    RECEIVE_WINDOW_ADJUST_LOCAL_EOF,
    RECEIVE_WINDOW_ADJUST_REMOTE_EOF,
    RECEIVE_WINDOW_ADJUST_BOTH_EOF,
    SEND_EOF_OPEN,
    SEND_EOF_REMOTE_EOF,
    RECEIVE_EOF_OPEN,
    RECEIVE_EOF_LOCAL_EOF,
    SEND_CLOSE_OPEN,
    SEND_CLOSE_LOCAL_EOF,
    SEND_CLOSE_REMOTE_EOF,
    SEND_CLOSE_BOTH_EOF,
    RECEIVE_CLOSE_OPEN,
    RECEIVE_CLOSE_LOCAL_EOF,
    RECEIVE_CLOSE_REMOTE_EOF,
    RECEIVE_CLOSE_BOTH_EOF,
    RECEIVE_CLOSE_CLOSE_SENT,
    DISCONNECT_OPENING,
    DISCONNECT_OPEN,
    DISCONNECT_LOCAL_EOF,
    DISCONNECT_REMOTE_EOF,
    DISCONNECT_BOTH_EOF,
    DISCONNECT_CLOSE_SENT,
}

internal data class SshChannelTransitionMeta(
    val id: SshChannelTransitionId,
    val eventId: SshChannelEventId,
    val source: SshChannelState,
    val target: SshChannelState,
    val effects: Set<SshChannelEffect>,
    val scope: SshChannelOperationScope,
    val requiresAuthenticatedConnection: Boolean,
) : MetaInfo

internal data class SshChannelFormalTransition(
    val id: SshChannelTransitionId,
    val eventId: SshChannelEventId,
    val source: SshChannelState,
    val target: SshChannelState,
    val effects: Set<SshChannelEffect>,
    val scope: SshChannelOperationScope,
    val requiresAuthenticatedConnection: Boolean,
) {
    val eventName: String
        get() = eventId.tlaName
}

internal data class SshChannelFormalOperation(
    val id: String,
    val eventId: SshChannelEventId,
    val sourceStateName: String,
    val targetStateName: String,
    val effects: Set<SshChannelEffect>,
    val scope: SshChannelOperationScope,
    val requiresAuthenticatedConnection: Boolean,
) {
    val eventName: String
        get() = eventId.tlaName
}

internal data class SshChannelFormalModel(
    val states: Set<SshChannelState>,
    val transitions: List<SshChannelFormalTransition>,
    val operations: List<SshChannelFormalOperation>,
    val unallocatedStateName: String,
    val rejectedOperationEffects: Set<SshChannelEffect>,
) {
    init {
        require(states == SshChannelState.entries.toSet())
        require(transitions.map(SshChannelFormalTransition::id).toSet() == SshChannelTransitionId.entries.toSet())
        require(transitions.map(SshChannelFormalTransition::id).distinct().size == transitions.size)
        require(operations.map(SshChannelFormalOperation::id).distinct().size == operations.size)
        require(operations.mapTo(mutableSetOf(), SshChannelFormalOperation::eventId) == SshChannelEventId.entries.toSet())
        require(operations.count { it.scope == SshChannelOperationScope.CHANNEL_ATTEMPT } > 0)
    }
}

/**
 * Per-channel KStateMachine source of truth.
 *
 * [process] serializes event delivery because inbound packets and application calls may arrive on
 * different coroutines. A rejected event performs no transition; callers must not perform the
 * corresponding packet, window, or stream side effect when this returns `false`.
 */
internal class SshChannelStateMachine(
    initialState: SshChannelState,
) {
    init {
        require(initialState == SshChannelState.OPENING || initialState == SshChannelState.OPEN) {
            "A channel must be created while opening or already open"
        }
    }

    private sealed class ChannelEvent(
        val id: SshChannelEventId,
        val effects: Set<SshChannelEffect>,
        val scope: SshChannelOperationScope = SshChannelOperationScope.CHANNEL_ATTEMPT,
        val requiresAuthenticatedConnection: Boolean = true,
    ) : Event {
        data object OpenConfirmed : ChannelEvent(
            SshChannelEventId.OPEN_CONFIRMED,
            setOf(SshChannelEffect.COMPLETE_OPEN),
            scope = SshChannelOperationScope.CONNECTION_TRANSITION,
        )
        data object OpenFailed : ChannelEvent(
            SshChannelEventId.OPEN_FAILED,
            setOf(SshChannelEffect.FAIL_OPEN),
            scope = SshChannelOperationScope.CONNECTION_TRANSITION,
        )
        data object SendData : ChannelEvent(SshChannelEventId.SEND_DATA, setOf(SshChannelEffect.SEND_DATA))
        data object ReceiveData : ChannelEvent(SshChannelEventId.RECEIVE_DATA, setOf(SshChannelEffect.DELIVER_DATA))
        data object SendRequest : ChannelEvent(
            SshChannelEventId.SEND_REQUEST,
            setOf(SshChannelEffect.SEND_REQUEST),
            scope = SshChannelOperationScope.CONNECTION_TRANSITION,
        )
        data object ReceiveRequest : ChannelEvent(SshChannelEventId.RECEIVE_REQUEST, setOf(SshChannelEffect.DELIVER_REQUEST))
        data object ReceiveWindowAdjust : ChannelEvent(SshChannelEventId.RECEIVE_WINDOW_ADJUST, setOf(SshChannelEffect.ADJUST_WINDOW))
        data object SendEof : ChannelEvent(SshChannelEventId.SEND_EOF, setOf(SshChannelEffect.SEND_EOF))
        data object ReceiveEof : ChannelEvent(SshChannelEventId.RECEIVE_EOF, setOf(SshChannelEffect.CLOSE_INBOUND_STREAMS))
        data object SendClose : ChannelEvent(SshChannelEventId.SEND_CLOSE, setOf(SshChannelEffect.SEND_CLOSE, SshChannelEffect.CLOSE_CHANNEL))
        data object ReceiveClose : ChannelEvent(SshChannelEventId.RECEIVE_CLOSE, setOf(SshChannelEffect.SEND_CLOSE, SshChannelEffect.CLOSE_CHANNEL))
        data object Disconnect : ChannelEvent(
            SshChannelEventId.DISCONNECT,
            setOf(SshChannelEffect.CLOSE_CHANNEL),
            scope = SshChannelOperationScope.CONNECTION_TEARDOWN,
            requiresAuthenticatedConnection = false,
        )
    }

    private val eventMutex = Mutex()

    @Volatile
    private var activeState = initialState

    private val stateMachine: StateMachine = createStdLibStateMachine {
        lateinit var opening: State
        lateinit var open: State

        if (initialState == SshChannelState.OPENING) {
            opening = initialState(SshChannelState.OPENING.name)
            open = state(SshChannelState.OPEN.name)
        } else {
            opening = state(SshChannelState.OPENING.name)
            open = initialState(SshChannelState.OPEN.name)
        }

        val localEof = state(SshChannelState.LOCAL_EOF.name)
        val remoteEof = state(SshChannelState.REMOTE_EOF.name)
        val bothEof = state(SshChannelState.BOTH_EOF.name)
        val closeSent = state(SshChannelState.CLOSE_SENT.name)
        val closed = finalState(SshChannelState.CLOSED.name)

        bindState(opening, SshChannelState.OPENING)
        bindState(open, SshChannelState.OPEN)
        bindState(localEof, SshChannelState.LOCAL_EOF)
        bindState(remoteEof, SshChannelState.REMOTE_EOF)
        bindState(bothEof, SshChannelState.BOTH_EOF)
        bindState(closeSent, SshChannelState.CLOSE_SENT)
        bindState(closed, SshChannelState.CLOSED)

        opening.channelTransition(ChannelEvent.OpenConfirmed, SshChannelTransitionId.OPEN_CONFIRMED, open)
        opening.channelTransition(ChannelEvent.OpenFailed, SshChannelTransitionId.OPEN_FAILED, closed)

        open.channelTransition(ChannelEvent.SendData, SshChannelTransitionId.SEND_DATA_OPEN)
        remoteEof.channelTransition(ChannelEvent.SendData, SshChannelTransitionId.SEND_DATA_REMOTE_EOF)
        open.channelTransition(ChannelEvent.ReceiveData, SshChannelTransitionId.RECEIVE_DATA_OPEN)
        localEof.channelTransition(ChannelEvent.ReceiveData, SshChannelTransitionId.RECEIVE_DATA_LOCAL_EOF)

        open.channelTransition(ChannelEvent.SendRequest, SshChannelTransitionId.SEND_REQUEST_OPEN)
        localEof.channelTransition(ChannelEvent.SendRequest, SshChannelTransitionId.SEND_REQUEST_LOCAL_EOF)
        remoteEof.channelTransition(ChannelEvent.SendRequest, SshChannelTransitionId.SEND_REQUEST_REMOTE_EOF)
        bothEof.channelTransition(ChannelEvent.SendRequest, SshChannelTransitionId.SEND_REQUEST_BOTH_EOF)
        open.channelTransition(ChannelEvent.ReceiveRequest, SshChannelTransitionId.RECEIVE_REQUEST_OPEN)
        localEof.channelTransition(ChannelEvent.ReceiveRequest, SshChannelTransitionId.RECEIVE_REQUEST_LOCAL_EOF)
        remoteEof.channelTransition(ChannelEvent.ReceiveRequest, SshChannelTransitionId.RECEIVE_REQUEST_REMOTE_EOF)
        bothEof.channelTransition(ChannelEvent.ReceiveRequest, SshChannelTransitionId.RECEIVE_REQUEST_BOTH_EOF)

        open.channelTransition(ChannelEvent.ReceiveWindowAdjust, SshChannelTransitionId.RECEIVE_WINDOW_ADJUST_OPEN)
        localEof.channelTransition(ChannelEvent.ReceiveWindowAdjust, SshChannelTransitionId.RECEIVE_WINDOW_ADJUST_LOCAL_EOF)
        remoteEof.channelTransition(ChannelEvent.ReceiveWindowAdjust, SshChannelTransitionId.RECEIVE_WINDOW_ADJUST_REMOTE_EOF)
        bothEof.channelTransition(ChannelEvent.ReceiveWindowAdjust, SshChannelTransitionId.RECEIVE_WINDOW_ADJUST_BOTH_EOF)

        open.channelTransition(ChannelEvent.SendEof, SshChannelTransitionId.SEND_EOF_OPEN, localEof)
        remoteEof.channelTransition(ChannelEvent.SendEof, SshChannelTransitionId.SEND_EOF_REMOTE_EOF, bothEof)
        open.channelTransition(ChannelEvent.ReceiveEof, SshChannelTransitionId.RECEIVE_EOF_OPEN, remoteEof)
        localEof.channelTransition(ChannelEvent.ReceiveEof, SshChannelTransitionId.RECEIVE_EOF_LOCAL_EOF, bothEof)

        open.channelTransition(ChannelEvent.SendClose, SshChannelTransitionId.SEND_CLOSE_OPEN, closeSent)
        localEof.channelTransition(ChannelEvent.SendClose, SshChannelTransitionId.SEND_CLOSE_LOCAL_EOF, closeSent)
        remoteEof.channelTransition(ChannelEvent.SendClose, SshChannelTransitionId.SEND_CLOSE_REMOTE_EOF, closeSent)
        bothEof.channelTransition(ChannelEvent.SendClose, SshChannelTransitionId.SEND_CLOSE_BOTH_EOF, closeSent)

        open.channelTransition(ChannelEvent.ReceiveClose, SshChannelTransitionId.RECEIVE_CLOSE_OPEN, closed)
        localEof.channelTransition(ChannelEvent.ReceiveClose, SshChannelTransitionId.RECEIVE_CLOSE_LOCAL_EOF, closed)
        remoteEof.channelTransition(ChannelEvent.ReceiveClose, SshChannelTransitionId.RECEIVE_CLOSE_REMOTE_EOF, closed)
        bothEof.channelTransition(ChannelEvent.ReceiveClose, SshChannelTransitionId.RECEIVE_CLOSE_BOTH_EOF, closed)
        closeSent.channelTransition(
            ChannelEvent.ReceiveClose,
            SshChannelTransitionId.RECEIVE_CLOSE_CLOSE_SENT,
            closed,
            effects = setOf(SshChannelEffect.CLOSE_CHANNEL),
        )

        opening.channelTransition(ChannelEvent.Disconnect, SshChannelTransitionId.DISCONNECT_OPENING, closed)
        open.channelTransition(ChannelEvent.Disconnect, SshChannelTransitionId.DISCONNECT_OPEN, closed)
        localEof.channelTransition(ChannelEvent.Disconnect, SshChannelTransitionId.DISCONNECT_LOCAL_EOF, closed)
        remoteEof.channelTransition(ChannelEvent.Disconnect, SshChannelTransitionId.DISCONNECT_REMOTE_EOF, closed)
        bothEof.channelTransition(ChannelEvent.Disconnect, SshChannelTransitionId.DISCONNECT_BOTH_EOF, closed)
        closeSent.channelTransition(ChannelEvent.Disconnect, SshChannelTransitionId.DISCONNECT_CLOSE_SENT, closed)
    }

    val state: SshChannelState
        get() = activeState

    val isOpen: Boolean
        get() = activeState !in setOf(SshChannelState.CLOSE_SENT, SshChannelState.CLOSED)

    suspend fun openConfirmed() = process(ChannelEvent.OpenConfirmed)
    suspend fun openFailed() = process(ChannelEvent.OpenFailed)
    suspend fun sendData() = process(ChannelEvent.SendData)
    suspend fun receiveData() = process(ChannelEvent.ReceiveData)
    suspend fun sendRequest() = process(ChannelEvent.SendRequest)
    suspend fun receiveRequest() = process(ChannelEvent.ReceiveRequest)
    suspend fun receiveWindowAdjust() = process(ChannelEvent.ReceiveWindowAdjust)
    suspend fun sendEof() = process(ChannelEvent.SendEof)
    suspend fun receiveEof() = process(ChannelEvent.ReceiveEof)
    suspend fun sendClose() = process(ChannelEvent.SendClose)
    suspend fun receiveClose() = process(ChannelEvent.ReceiveClose)
    suspend fun disconnect() = process(ChannelEvent.Disconnect)

    internal fun formalModel(): SshChannelFormalModel {
        val states = collectChannelStates(stateMachine)
        val transitions = states.flatMap { state ->
            state.transitions.mapNotNull { transition ->
                val meta = transition.metaInfo as? SshChannelTransitionMeta ?: return@mapNotNull null
                SshChannelFormalTransition(
                    meta.id,
                    meta.eventId,
                    meta.source,
                    meta.target,
                    meta.effects,
                    meta.scope,
                    meta.requiresAuthenticatedConnection,
                )
            }
        }
        val runtimeOperations = transitions.map { transition ->
            SshChannelFormalOperation(
                id = transition.id.name,
                eventId = transition.eventId,
                sourceStateName = transition.source.name,
                targetStateName = transition.target.name,
                effects = transition.effects,
                scope = transition.scope,
                requiresAuthenticatedConnection = transition.requiresAuthenticatedConnection,
            )
        }
        val constructionOperations = listOf(
            SshChannelFormalOperation(
                id = SshChannelConstructionId.ALLOCATE_LOCAL_OPEN.name,
                eventId = SshChannelEventId.ALLOCATE_LOCAL_OPEN,
                sourceStateName = UNALLOCATED_STATE,
                targetStateName = SshChannelState.OPENING.name,
                effects = setOf(SshChannelEffect.SEND_OPEN),
                scope = SshChannelOperationScope.CONNECTION_TRANSITION,
                requiresAuthenticatedConnection = true,
            ),
            SshChannelFormalOperation(
                id = SshChannelConstructionId.ACCEPT_REMOTE_OPEN.name,
                eventId = SshChannelEventId.ACCEPT_REMOTE_OPEN,
                sourceStateName = UNALLOCATED_STATE,
                targetStateName = SshChannelState.OPEN.name,
                effects = setOf(SshChannelEffect.SEND_OPEN_CONFIRMATION),
                scope = SshChannelOperationScope.CHANNEL_ATTEMPT,
                requiresAuthenticatedConnection = true,
            ),
        )
        return SshChannelFormalModel(
            states = states.mapNotNullTo(mutableSetOf()) { it.name?.let(SshChannelState::valueOf) },
            transitions = transitions,
            operations = runtimeOperations + constructionOperations,
            unallocatedStateName = UNALLOCATED_STATE,
            rejectedOperationEffects = emptySet(),
        )
    }

    private suspend fun process(event: ChannelEvent): Boolean = eventMutex.withLock {
        stateMachine.processEvent(event) == ProcessingResult.PROCESSED
    }

    private fun bindState(state: IState, lifecycleState: SshChannelState) {
        state.onEntry { activeState = lifecycleState }
    }

    private inline fun <reified E : ChannelEvent> IState.channelTransition(
        event: E,
        id: SshChannelTransitionId,
        target: State? = null,
        effects: Set<SshChannelEffect> = event.effects,
    ) {
        transition<E>(id.name) {
            targetState = target
            metaInfo = SshChannelTransitionMeta(
                id = id,
                eventId = event.id,
                source = SshChannelState.valueOf(requireNotNull(this@channelTransition.name)),
                target = target?.name?.let(SshChannelState::valueOf)
                    ?: SshChannelState.valueOf(requireNotNull(this@channelTransition.name)),
                effects = effects,
                scope = event.scope,
                requiresAuthenticatedConnection = event.requiresAuthenticatedConnection,
            )
        }
    }

    companion object {
        private const val UNALLOCATED_STATE = "Unallocated"
    }
}

private fun collectChannelStates(root: IState): List<IState> = buildList {
    add(root)
    root.states.forEach { addAll(collectChannelStates(it)) }
}

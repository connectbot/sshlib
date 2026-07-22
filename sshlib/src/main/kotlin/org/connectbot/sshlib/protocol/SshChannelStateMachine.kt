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
    val eventName: String,
    val source: SshChannelState,
    val target: SshChannelState,
) : MetaInfo

internal data class SshChannelFormalTransition(
    val id: SshChannelTransitionId,
    val eventName: String,
    val source: SshChannelState,
    val target: SshChannelState,
)

internal data class SshChannelFormalModel(
    val states: Set<SshChannelState>,
    val transitions: List<SshChannelFormalTransition>,
) {
    init {
        require(states == SshChannelState.entries.toSet())
        require(transitions.map(SshChannelFormalTransition::id).toSet() == SshChannelTransitionId.entries.toSet())
        require(transitions.map(SshChannelFormalTransition::id).distinct().size == transitions.size)
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

    private sealed interface ChannelEvent : Event {
        data object OpenConfirmed : ChannelEvent
        data object OpenFailed : ChannelEvent
        data object SendData : ChannelEvent
        data object ReceiveData : ChannelEvent
        data object SendRequest : ChannelEvent
        data object ReceiveRequest : ChannelEvent
        data object ReceiveWindowAdjust : ChannelEvent
        data object SendEof : ChannelEvent
        data object ReceiveEof : ChannelEvent
        data object SendClose : ChannelEvent
        data object ReceiveClose : ChannelEvent
        data object Disconnect : ChannelEvent
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

        opening.channelTransition<ChannelEvent.OpenConfirmed>(SshChannelTransitionId.OPEN_CONFIRMED, open)
        opening.channelTransition<ChannelEvent.OpenFailed>(SshChannelTransitionId.OPEN_FAILED, closed)

        open.channelTransition<ChannelEvent.SendData>(SshChannelTransitionId.SEND_DATA_OPEN)
        remoteEof.channelTransition<ChannelEvent.SendData>(SshChannelTransitionId.SEND_DATA_REMOTE_EOF)
        open.channelTransition<ChannelEvent.ReceiveData>(SshChannelTransitionId.RECEIVE_DATA_OPEN)
        localEof.channelTransition<ChannelEvent.ReceiveData>(SshChannelTransitionId.RECEIVE_DATA_LOCAL_EOF)

        open.channelTransition<ChannelEvent.SendRequest>(SshChannelTransitionId.SEND_REQUEST_OPEN)
        localEof.channelTransition<ChannelEvent.SendRequest>(SshChannelTransitionId.SEND_REQUEST_LOCAL_EOF)
        remoteEof.channelTransition<ChannelEvent.SendRequest>(SshChannelTransitionId.SEND_REQUEST_REMOTE_EOF)
        bothEof.channelTransition<ChannelEvent.SendRequest>(SshChannelTransitionId.SEND_REQUEST_BOTH_EOF)
        open.channelTransition<ChannelEvent.ReceiveRequest>(SshChannelTransitionId.RECEIVE_REQUEST_OPEN)
        localEof.channelTransition<ChannelEvent.ReceiveRequest>(SshChannelTransitionId.RECEIVE_REQUEST_LOCAL_EOF)
        remoteEof.channelTransition<ChannelEvent.ReceiveRequest>(SshChannelTransitionId.RECEIVE_REQUEST_REMOTE_EOF)
        bothEof.channelTransition<ChannelEvent.ReceiveRequest>(SshChannelTransitionId.RECEIVE_REQUEST_BOTH_EOF)

        open.channelTransition<ChannelEvent.ReceiveWindowAdjust>(SshChannelTransitionId.RECEIVE_WINDOW_ADJUST_OPEN)
        localEof.channelTransition<ChannelEvent.ReceiveWindowAdjust>(SshChannelTransitionId.RECEIVE_WINDOW_ADJUST_LOCAL_EOF)
        remoteEof.channelTransition<ChannelEvent.ReceiveWindowAdjust>(SshChannelTransitionId.RECEIVE_WINDOW_ADJUST_REMOTE_EOF)
        bothEof.channelTransition<ChannelEvent.ReceiveWindowAdjust>(SshChannelTransitionId.RECEIVE_WINDOW_ADJUST_BOTH_EOF)

        open.channelTransition<ChannelEvent.SendEof>(SshChannelTransitionId.SEND_EOF_OPEN, localEof)
        remoteEof.channelTransition<ChannelEvent.SendEof>(SshChannelTransitionId.SEND_EOF_REMOTE_EOF, bothEof)
        open.channelTransition<ChannelEvent.ReceiveEof>(SshChannelTransitionId.RECEIVE_EOF_OPEN, remoteEof)
        localEof.channelTransition<ChannelEvent.ReceiveEof>(SshChannelTransitionId.RECEIVE_EOF_LOCAL_EOF, bothEof)

        open.channelTransition<ChannelEvent.SendClose>(SshChannelTransitionId.SEND_CLOSE_OPEN, closeSent)
        localEof.channelTransition<ChannelEvent.SendClose>(SshChannelTransitionId.SEND_CLOSE_LOCAL_EOF, closeSent)
        remoteEof.channelTransition<ChannelEvent.SendClose>(SshChannelTransitionId.SEND_CLOSE_REMOTE_EOF, closeSent)
        bothEof.channelTransition<ChannelEvent.SendClose>(SshChannelTransitionId.SEND_CLOSE_BOTH_EOF, closeSent)

        open.channelTransition<ChannelEvent.ReceiveClose>(SshChannelTransitionId.RECEIVE_CLOSE_OPEN, closed)
        localEof.channelTransition<ChannelEvent.ReceiveClose>(SshChannelTransitionId.RECEIVE_CLOSE_LOCAL_EOF, closed)
        remoteEof.channelTransition<ChannelEvent.ReceiveClose>(SshChannelTransitionId.RECEIVE_CLOSE_REMOTE_EOF, closed)
        bothEof.channelTransition<ChannelEvent.ReceiveClose>(SshChannelTransitionId.RECEIVE_CLOSE_BOTH_EOF, closed)
        closeSent.channelTransition<ChannelEvent.ReceiveClose>(SshChannelTransitionId.RECEIVE_CLOSE_CLOSE_SENT, closed)

        opening.channelTransition<ChannelEvent.Disconnect>(SshChannelTransitionId.DISCONNECT_OPENING, closed)
        open.channelTransition<ChannelEvent.Disconnect>(SshChannelTransitionId.DISCONNECT_OPEN, closed)
        localEof.channelTransition<ChannelEvent.Disconnect>(SshChannelTransitionId.DISCONNECT_LOCAL_EOF, closed)
        remoteEof.channelTransition<ChannelEvent.Disconnect>(SshChannelTransitionId.DISCONNECT_REMOTE_EOF, closed)
        bothEof.channelTransition<ChannelEvent.Disconnect>(SshChannelTransitionId.DISCONNECT_BOTH_EOF, closed)
        closeSent.channelTransition<ChannelEvent.Disconnect>(SshChannelTransitionId.DISCONNECT_CLOSE_SENT, closed)
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
                SshChannelFormalTransition(meta.id, meta.eventName, meta.source, meta.target)
            }
        }
        return SshChannelFormalModel(
            states = states.mapNotNullTo(mutableSetOf()) { it.name?.let(SshChannelState::valueOf) },
            transitions = transitions,
        )
    }

    private suspend fun process(event: ChannelEvent): Boolean = eventMutex.withLock {
        stateMachine.processEvent(event) == ProcessingResult.PROCESSED
    }

    private fun bindState(state: IState, lifecycleState: SshChannelState) {
        state.onEntry { activeState = lifecycleState }
    }

    private inline fun <reified E : ChannelEvent> IState.channelTransition(
        id: SshChannelTransitionId,
        target: State? = null,
    ) {
        transition<E>(id.name) {
            targetState = target
            metaInfo = SshChannelTransitionMeta(
                id = id,
                eventName = requireNotNull(E::class.simpleName),
                source = SshChannelState.valueOf(requireNotNull(this@channelTransition.name)),
                target = target?.name?.let(SshChannelState::valueOf)
                    ?: SshChannelState.valueOf(requireNotNull(this@channelTransition.name)),
            )
        }
    }
}

private fun collectChannelStates(root: IState): List<IState> = buildList {
    add(root)
    root.states.forEach { addAll(collectChannelStates(it)) }
}

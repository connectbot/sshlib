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
import ru.nsk.kstatemachine.transition.onTriggered

/**
 * Protocol lifecycle states for an SFTP session (draft-ietf-secsh-filexfer-02).
 */
internal enum class SftpState {
    UNINITIALIZED,
    WAIT_VERSION,
    READY,
    CLOSED,
}

/**
 * Lifecycle states for individual SFTP file/directory handles.
 */
internal enum class SftpHandleState {
    Unallocated,
    PendingFile,
    PendingDir,
    OpenFile,
    OpenDir,
    Closed,
}

internal enum class SftpEffect {
    SEND_INIT,
    RECEIVE_VERSION,
    SEND_OPEN_FILE,
    SEND_OPEN_DIR,
    SEND_READ,
    SEND_WRITE,
    SEND_READDIR,
    SEND_CLOSE_HANDLE,
    SEND_REQUEST,
    DELIVER_HANDLE,
    DELIVER_DATA,
    DELIVER_NAME,
    DELIVER_ATTRS,
    DELIVER_STATUS,
    DISCONNECT_SFTP,
}

internal enum class SftpEventId(val tlaName: String) {
    SEND_INIT("SendInit"),
    RECEIVE_VERSION("ReceiveVersion"),
    OPEN_FILE("OpenFile"),
    OPEN_DIR("OpenDir"),
    READ_FILE("ReadFile"),
    WRITE_FILE("WriteFile"),
    READ_DIR("ReadDir"),
    CLOSE_HANDLE("CloseHandle"),
    REQUEST("Request"),
    RECEIVE_HANDLE("ReceiveHandle"),
    RECEIVE_DATA("ReceiveData"),
    RECEIVE_NAME("ReceiveName"),
    RECEIVE_ATTRS("ReceiveAttrs"),
    RECEIVE_STATUS("ReceiveStatus"),
    DISCONNECT("Disconnect"),
}

internal enum class SftpEventOrigin {
    LOCAL_COMMAND,
    PARSED_PACKET,
    CONNECTION_CONTROL,
}

internal enum class SftpTransitionId {
    SEND_INIT_UNINITIALIZED,
    RECEIVE_VERSION_WAIT_VERSION,
    OPEN_FILE_READY,
    OPEN_DIR_READY,
    READ_FILE_READY,
    WRITE_FILE_READY,
    READ_DIR_READY,
    CLOSE_HANDLE_READY,
    REQUEST_READY,
    RECEIVE_HANDLE_READY,
    RECEIVE_DATA_READY,
    RECEIVE_NAME_READY,
    RECEIVE_ATTRS_READY,
    RECEIVE_STATUS_READY,
    DISCONNECT_UNINITIALIZED,
    DISCONNECT_WAIT_VERSION,
    DISCONNECT_READY,
}

internal enum class SftpPendingRequest(val tlaName: String) {
    OPEN("PendingOpen"),
    READ("PendingRead"),
    WRITE("PendingWrite"),
    READ_DIR("PendingReadDir"),
    CLOSE("PendingClose"),
    REQUEST("PendingRequest"),
}

internal data class SftpTransitionMeta(
    val id: SftpTransitionId,
    val eventId: SftpEventId,
    val source: SftpState,
    val target: SftpState,
    val effects: Set<SftpEffect>,
    val origin: SftpEventOrigin,
    val requiresReadySession: Boolean,
    val expectsPending: SftpPendingRequest? = null,
) : MetaInfo

internal data class SftpAcceptedTransition(
    val id: SftpTransitionId,
    val effects: Set<SftpEffect>,
    val origin: SftpEventOrigin,
)

internal data class SftpFormalTransition(
    val id: SftpTransitionId,
    val eventId: SftpEventId,
    val source: SftpState,
    val target: SftpState,
    val effects: Set<SftpEffect>,
    val origin: SftpEventOrigin,
    val requiresReadySession: Boolean,
    val expectsPending: SftpPendingRequest? = null,
)

internal data class SftpFormalModel(
    val states: Set<SftpState>,
    val transitions: List<SftpFormalTransition>,
)

/**
 * Source of truth for SFTP Client State Machine.
 */
internal class SftpStateMachine {
    private sealed class SftpEvent(
        val id: SftpEventId,
        val effects: Set<SftpEffect>,
        val origin: SftpEventOrigin,
        val action: suspend (SftpAcceptedTransition) -> Unit,
        val requiresReadySession: Boolean = true,
    ) : Event {
        class SendInit(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.SEND_INIT,
                setOf(SftpEffect.SEND_INIT),
                SftpEventOrigin.LOCAL_COMMAND,
                action,
                requiresReadySession = false,
            )

        class ReceiveVersion(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.RECEIVE_VERSION,
                setOf(SftpEffect.RECEIVE_VERSION),
                SftpEventOrigin.PARSED_PACKET,
                action,
                requiresReadySession = false,
            )

        class OpenFile(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.OPEN_FILE,
                setOf(SftpEffect.SEND_OPEN_FILE),
                SftpEventOrigin.LOCAL_COMMAND,
                action,
            )

        class OpenDir(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.OPEN_DIR,
                setOf(SftpEffect.SEND_OPEN_DIR),
                SftpEventOrigin.LOCAL_COMMAND,
                action,
            )

        class ReadFile(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.READ_FILE,
                setOf(SftpEffect.SEND_READ),
                SftpEventOrigin.LOCAL_COMMAND,
                action,
            )

        class WriteFile(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.WRITE_FILE,
                setOf(SftpEffect.SEND_WRITE),
                SftpEventOrigin.LOCAL_COMMAND,
                action,
            )

        class ReadDir(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.READ_DIR,
                setOf(SftpEffect.SEND_READDIR),
                SftpEventOrigin.LOCAL_COMMAND,
                action,
            )

        class CloseHandle(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.CLOSE_HANDLE,
                setOf(SftpEffect.SEND_CLOSE_HANDLE),
                SftpEventOrigin.LOCAL_COMMAND,
                action,
            )

        class Request(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.REQUEST,
                setOf(SftpEffect.SEND_REQUEST),
                SftpEventOrigin.LOCAL_COMMAND,
                action,
            )

        class ReceiveHandle(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.RECEIVE_HANDLE,
                setOf(SftpEffect.DELIVER_HANDLE),
                SftpEventOrigin.PARSED_PACKET,
                action,
            )

        class ReceiveData(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.RECEIVE_DATA,
                setOf(SftpEffect.DELIVER_DATA),
                SftpEventOrigin.PARSED_PACKET,
                action,
            )

        class ReceiveName(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.RECEIVE_NAME,
                setOf(SftpEffect.DELIVER_NAME),
                SftpEventOrigin.PARSED_PACKET,
                action,
            )

        class ReceiveAttrs(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.RECEIVE_ATTRS,
                setOf(SftpEffect.DELIVER_ATTRS),
                SftpEventOrigin.PARSED_PACKET,
                action,
            )

        class ReceiveStatus(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.RECEIVE_STATUS,
                setOf(SftpEffect.DELIVER_STATUS),
                SftpEventOrigin.PARSED_PACKET,
                action,
            )

        class Disconnect(action: suspend (SftpAcceptedTransition) -> Unit) :
            SftpEvent(
                SftpEventId.DISCONNECT,
                setOf(SftpEffect.DISCONNECT_SFTP),
                SftpEventOrigin.CONNECTION_CONTROL,
                action,
                requiresReadySession = false,
            )
    }

    private enum class PendingRequestKind {
        OPEN,
        READ,
        READ_DIR,
        GENERIC,
    }

    private val mutex = Mutex()
    private val pendingRequests = mutableListOf<PendingRequestKind>()

    @Volatile
    private var activeState: SftpState = SftpState.UNINITIALIZED

    private val stateMachine: StateMachine = createStdLibStateMachine {
        val uninitialized = initialState(SftpState.UNINITIALIZED.name)
        val waitVersion = state(SftpState.WAIT_VERSION.name)
        val ready = state(SftpState.READY.name)
        val closed = finalState(SftpState.CLOSED.name)

        bindState(uninitialized, SftpState.UNINITIALIZED)
        bindState(waitVersion, SftpState.WAIT_VERSION)
        bindState(ready, SftpState.READY)
        bindState(closed, SftpState.CLOSED)

        uninitialized.sftpTransition(
            SftpEvent.SendInit {},
            SftpTransitionId.SEND_INIT_UNINITIALIZED,
            target = waitVersion,
        )
        waitVersion.sftpTransition(
            SftpEvent.ReceiveVersion {},
            SftpTransitionId.RECEIVE_VERSION_WAIT_VERSION,
            target = ready,
        )

        ready.sftpTransition(
            SftpEvent.OpenFile {},
            SftpTransitionId.OPEN_FILE_READY,
            onEffect = { pendingRequests.add(PendingRequestKind.OPEN) },
        )
        ready.sftpTransition(
            SftpEvent.OpenDir {},
            SftpTransitionId.OPEN_DIR_READY,
            onEffect = { pendingRequests.add(PendingRequestKind.OPEN) },
        )
        ready.sftpTransition(
            SftpEvent.ReadFile {},
            SftpTransitionId.READ_FILE_READY,
            onEffect = { pendingRequests.add(PendingRequestKind.READ) },
        )
        ready.sftpTransition(
            SftpEvent.WriteFile {},
            SftpTransitionId.WRITE_FILE_READY,
            onEffect = { pendingRequests.add(PendingRequestKind.GENERIC) },
        )
        ready.sftpTransition(
            SftpEvent.ReadDir {},
            SftpTransitionId.READ_DIR_READY,
            onEffect = { pendingRequests.add(PendingRequestKind.READ_DIR) },
        )
        ready.sftpTransition(
            SftpEvent.CloseHandle {},
            SftpTransitionId.CLOSE_HANDLE_READY,
            onEffect = { pendingRequests.add(PendingRequestKind.GENERIC) },
        )
        ready.sftpTransition(
            SftpEvent.Request {},
            SftpTransitionId.REQUEST_READY,
            onEffect = { pendingRequests.add(PendingRequestKind.GENERIC) },
        )

        ready.sftpTransition(
            SftpEvent.ReceiveHandle {},
            SftpTransitionId.RECEIVE_HANDLE_READY,
            expectsPending = SftpPendingRequest.OPEN,
            guard = { pendingRequests.contains(PendingRequestKind.OPEN) },
            onEffect = { pendingRequests.remove(PendingRequestKind.OPEN) },
        )
        ready.sftpTransition(
            SftpEvent.ReceiveData {},
            SftpTransitionId.RECEIVE_DATA_READY,
            expectsPending = SftpPendingRequest.READ,
            guard = { pendingRequests.contains(PendingRequestKind.READ) },
            onEffect = { pendingRequests.remove(PendingRequestKind.READ) },
        )
        ready.sftpTransition(
            SftpEvent.ReceiveName {},
            SftpTransitionId.RECEIVE_NAME_READY,
            expectsPending = SftpPendingRequest.READ_DIR,
            guard = { pendingRequests.contains(PendingRequestKind.READ_DIR) },
            onEffect = { pendingRequests.remove(PendingRequestKind.READ_DIR) },
        )
        ready.sftpTransition(
            SftpEvent.ReceiveAttrs {},
            SftpTransitionId.RECEIVE_ATTRS_READY,
            expectsPending = SftpPendingRequest.REQUEST,
            guard = { pendingRequests.contains(PendingRequestKind.GENERIC) },
            onEffect = { pendingRequests.remove(PendingRequestKind.GENERIC) },
        )
        ready.sftpTransition(
            SftpEvent.ReceiveStatus {},
            SftpTransitionId.RECEIVE_STATUS_READY,
            expectsPending = null,
            guard = { pendingRequests.isNotEmpty() },
            onEffect = {
                if (pendingRequests.isNotEmpty()) {
                    pendingRequests.removeAt(0)
                }
            },
        )

        uninitialized.sftpTransition(
            SftpEvent.Disconnect {},
            SftpTransitionId.DISCONNECT_UNINITIALIZED,
            target = closed,
            onEffect = { pendingRequests.clear() },
        )
        waitVersion.sftpTransition(
            SftpEvent.Disconnect {},
            SftpTransitionId.DISCONNECT_WAIT_VERSION,
            target = closed,
            onEffect = { pendingRequests.clear() },
        )
        ready.sftpTransition(
            SftpEvent.Disconnect {},
            SftpTransitionId.DISCONNECT_READY,
            target = closed,
            onEffect = { pendingRequests.clear() },
        )
    }

    val state: SftpState get() = activeState

    suspend fun sendInit(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.SendInit(action))
    suspend fun receiveVersion(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.ReceiveVersion(action))
    suspend fun openFile(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.OpenFile(action))
    suspend fun openDir(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.OpenDir(action))
    suspend fun readFile(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.ReadFile(action))
    suspend fun writeFile(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.WriteFile(action))
    suspend fun readDir(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.ReadDir(action))
    suspend fun closeHandle(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.CloseHandle(action))
    suspend fun request(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.Request(action))
    suspend fun receiveHandle(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.ReceiveHandle(action))
    suspend fun receiveData(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.ReceiveData(action))
    suspend fun receiveName(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.ReceiveName(action))
    suspend fun receiveAttrs(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.ReceiveAttrs(action))
    suspend fun receiveStatus(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.ReceiveStatus(action))
    suspend fun disconnect(action: suspend (SftpAcceptedTransition) -> Unit) = process(SftpEvent.Disconnect(action))

    internal fun formalModel(): SftpFormalModel {
        val states = collectStates(stateMachine)
        val transitions = states.flatMap { state ->
            state.transitions.mapNotNull { transition ->
                val meta = transition.metaInfo as? SftpTransitionMeta ?: return@mapNotNull null
                SftpFormalTransition(
                    meta.id,
                    meta.eventId,
                    meta.source,
                    meta.target,
                    meta.effects,
                    meta.origin,
                    meta.requiresReadySession,
                    meta.expectsPending,
                )
            }
        }
        return SftpFormalModel(
            states = states.mapNotNullTo(mutableSetOf()) { it.name?.let(SftpState::valueOf) },
            transitions = transitions,
        )
    }

    private suspend fun process(event: SftpEvent): Boolean = mutex.withLock {
        val result = stateMachine.processEvent(event)
        if (result == ProcessingResult.PROCESSED) {
            true
        } else {
            false
        }
    }

    private fun bindState(state: IState, lifecycleState: SftpState) {
        state.onEntry { activeState = lifecycleState }
    }

    private inline fun <reified E : SftpEvent> IState.sftpTransition(
        event: E,
        id: SftpTransitionId,
        target: State? = null,
        effects: Set<SftpEffect> = event.effects,
        expectsPending: SftpPendingRequest? = null,
        noinline guard: (() -> Boolean)? = null,
        noinline onEffect: (() -> Unit)? = null,
    ) {
        transition<E>(id.name) {
            targetState = target
            if (guard != null) {
                this.guard = { guard() }
            }
            metaInfo = SftpTransitionMeta(
                id = id,
                eventId = event.id,
                source = SftpState.valueOf(requireNotNull(this@sftpTransition.name)),
                target = target?.name?.let(SftpState::valueOf)
                    ?: SftpState.valueOf(requireNotNull(this@sftpTransition.name)),
                effects = effects,
                origin = event.origin,
                requiresReadySession = event.requiresReadySession,
                expectsPending = expectsPending,
            )
        }.onTriggered {
            onEffect?.invoke()
            it.event.action(SftpAcceptedTransition(id, effects, event.origin))
        }
    }
}

private fun collectStates(root: IState): List<IState> = buildList {
    add(root)
    root.states.forEach { addAll(collectStates(it)) }
}

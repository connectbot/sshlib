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

package org.connectbot.sshlib.protocol

import ru.nsk.kstatemachine.event.Event
import ru.nsk.kstatemachine.event.StartEvent
import ru.nsk.kstatemachine.metainfo.MetaInfo
import ru.nsk.kstatemachine.state.FinalState
import ru.nsk.kstatemachine.state.HistoryState
import ru.nsk.kstatemachine.state.IState
import ru.nsk.kstatemachine.state.PseudoState
import ru.nsk.kstatemachine.statemachine.StateMachine
import java.security.MessageDigest
import kotlin.reflect.KClass

internal enum class SshTransitionId {
    BEGIN_AUTHENTICATION,
    REPEAT_BEGIN_AUTHENTICATION,
    AUTHENTICATION_SUCCESS,
    AUTHENTICATION_FAILURE,
    RECEIVE_USERAUTH_INFO_REQUEST,
    RECEIVE_USERAUTH_BANNER_READY,
    RECEIVE_USERAUTH_BANNER_AUTHENTICATING,
    AUTHORIZE_AUTHENTICATION_PACKET,
    AUTHORIZE_AUTHENTICATED_PACKET,
    RECEIVE_GLOBAL_REQUEST,
    OPEN_CHANNEL,
    RECEIVE_CHANNEL_OPEN_CONFIRMATION,
    RECEIVE_CHANNEL_OPEN_FAILURE,
    SEND_CHANNEL_REQUEST,
    RECEIVE_CHANNEL_SUCCESS,
    RECEIVE_CHANNEL_FAILURE,
    REKEY_STARTED,
    AUTHORIZE_POST_AUTH_EXT_INFO,
    AUTHORIZE_CONNECTION_PACKET,
    CONNECT,
    RECEIVE_VERSION,
    RECORD_NON_KEX_BEFORE_INITIAL_KEX_INIT,
    REJECT_NON_KEX_WAIT_KEX,
    REJECT_NON_KEX_WAIT_KEX_DH_GEX_INIT,
    REJECT_NON_KEX_WAIT_NEW_KEYS,
    REJECT_STRICT_KEX_INIT_NOT_FIRST,
    RECEIVE_INITIAL_STRICT_KEX_INIT,
    RECEIVE_INITIAL_NON_STRICT_KEX_INIT,
    RECEIVE_REKEY_KEX_INIT,
    RECEIVE_KEX_DH_REPLY,
    RECEIVE_KEX_ECDH_REPLY,
    RECEIVE_KEX_DH_GEX_GROUP,
    RECEIVE_KEX_DH_GEX_REPLY,
    RECEIVE_INITIAL_NEW_KEYS,
    RECEIVE_REKEY_NEW_KEYS,
    RECEIVE_SERVICE_ACCEPT,
    AUTHORIZE_SERVICE_EXT_INFO,
    RECEIVE_DEBUG,
    RECEIVE_IGNORE,
    UNEXPECTED_KEX_INIT_WAIT_KEX,
    UNEXPECTED_KEX_INIT_WAIT_KEX_DH_GEX_INIT,
    UNEXPECTED_KEX_INIT_WAIT_NEW_KEYS,
    DISCONNECT,
}

internal enum class SshEventOrigin {
    INTERNAL,
    LOCAL_COMMAND,
    PARSED_PACKET,
    TIMER,
}

internal enum class SshEffect {
    ACTIVATE_ENCRYPTION,
    ACTIVATE_INBOUND_PROTECTION,
    ACTIVATE_OUTBOUND_PROTECTION,
    AUTHENTICATION_FAILURE,
    AUTHENTICATION_SUCCESS,
    CLEAR_NON_KEX_BEFORE_INITIAL_KEX_INIT,
    DEBUG,
    DISCONNECT,
    IGNORE,
    ENABLE_STRICT_KEX,
    NEGOTIATE_NON_STRICT_KEX,
    RECEIVE_CHANNEL_FAILURE,
    RECEIVE_CHANNEL_OPEN_CONFIRMATION,
    RECEIVE_CHANNEL_OPEN_FAILURE,
    RECEIVE_CHANNEL_SUCCESS,
    RECEIVE_GLOBAL_REQUEST,
    RECEIVE_KEX_DH_GEX_REPLY,
    RECEIVE_KEX_DH_REPLY,
    RECEIVE_KEX_ECDH_REPLY,
    RECEIVE_KEX_INIT,
    RECEIVE_NEW_KEYS,
    RECEIVE_SERVICE_ACCEPT,
    RECEIVE_USERAUTH_BANNER,
    RECEIVE_USERAUTH_INFO_REQUEST,
    RECEIVE_VERSION,
    RECORD_NON_KEX_BEFORE_INITIAL_KEX_INIT,
    REKEY_COMPLETE,
    REKEY_STARTED,
    RESET_INBOUND_SEQUENCE,
    RESET_OUTBOUND_SEQUENCE,
    SEND_CHANNEL_OPEN,
    SEND_CHANNEL_REQUEST,
    SEND_CLIENT_EXT_INFO,
    SEND_KEX_DH_GEX_INIT,
    SEND_KEX_EXCHANGE_INIT,
    SEND_KEX_INIT,
    SEND_NEW_KEYS,
    SEND_SERVICE_REQUEST,
    SEND_PROTOCOL_ERROR,
    SEND_UNIMPLEMENTED,
    SEND_USERAUTH_REQUEST,
    SEND_VERSION,
    START_AUTHENTICATION,
    VERIFY_HOST_KEY_POSSESSION,
    VERIFY_KEX_TRANSCRIPT,
}

/**
 * Lifecycle-relevant packet classes used by the hostile-environment model.
 *
 * These deliberately abstract packets that have identical authorization and
 * state-machine behavior. Client-only classes are included so TLC can check
 * that receiving a syntactically valid packet never changes the endpoint's
 * role.
 */
internal enum class SshPacketClass {
    KEX_INIT,
    KEX_REPLY,
    KEX_GEX_GROUP,
    NEW_KEYS,
    SERVICE_ACCEPT,
    USERAUTH_SUCCESS,
    USERAUTH_FAILURE,
    USERAUTH_METHOD_SPECIFIC,
    USERAUTH_BANNER,
    EXT_INFO,
    CONNECTION_PACKET,
    CHANNEL_OPEN_REPLY,
    CHANNEL_REQUEST_REPLY,
    GLOBAL_REQUEST,
    DEBUG,
    IGNORE,
    DISCONNECT,
    CLIENT_KEX_INIT,
    CLIENT_SERVICE_REQUEST,
    CLIENT_USERAUTH_REQUEST,
    CLIENT_CONNECTION_PACKET,
    UNKNOWN,
}

internal enum class SshBooleanFact(
    val tlaName: String,
) {
    AUTH_REQUEST_PENDING("authRequestPending"),
    NON_KEX_BEFORE_INITIAL_KEX_INIT("nonKexBeforeInitialKexInit"),
    REKEYING("rekeying"),
    STRICT_KEX_ENABLED("strictKex"),
    ;

    fun evaluate(
        callbacks: SshClientCallbacks,
        strictKexEnabled: Boolean,
        nonKexBeforeInitialKexInit: Boolean,
    ): Boolean = when (this) {
        AUTH_REQUEST_PENDING -> callbacks.isAuthenticationRequestPending()
        NON_KEX_BEFORE_INITIAL_KEX_INIT -> nonKexBeforeInitialKexInit
        REKEYING -> callbacks.isRekeying()
        STRICT_KEX_ENABLED -> strictKexEnabled
    }
}

internal sealed interface SshFormalGuard {
    fun evaluate(
        callbacks: SshClientCallbacks,
        strictKexEnabled: Boolean,
        nonKexBeforeInitialKexInit: Boolean,
    ): Boolean

    fun renderTla(): String

    data object Always : SshFormalGuard {
        override fun evaluate(
            callbacks: SshClientCallbacks,
            strictKexEnabled: Boolean,
            nonKexBeforeInitialKexInit: Boolean,
        ) = true

        override fun renderTla() = "TRUE"
    }

    data class Fact(
        val fact: SshBooleanFact,
    ) : SshFormalGuard {
        override fun evaluate(
            callbacks: SshClientCallbacks,
            strictKexEnabled: Boolean,
            nonKexBeforeInitialKexInit: Boolean,
        ) = fact.evaluate(callbacks, strictKexEnabled, nonKexBeforeInitialKexInit)

        override fun renderTla() = fact.tlaName
    }

    data class Not(
        val expression: SshFormalGuard,
    ) : SshFormalGuard {
        override fun evaluate(
            callbacks: SshClientCallbacks,
            strictKexEnabled: Boolean,
            nonKexBeforeInitialKexInit: Boolean,
        ) = !expression.evaluate(callbacks, strictKexEnabled, nonKexBeforeInitialKexInit)

        override fun renderTla() = "~(${expression.renderTla()})"
    }

    data class And(
        val left: SshFormalGuard,
        val right: SshFormalGuard,
    ) : SshFormalGuard {
        override fun evaluate(
            callbacks: SshClientCallbacks,
            strictKexEnabled: Boolean,
            nonKexBeforeInitialKexInit: Boolean,
        ) = left.evaluate(callbacks, strictKexEnabled, nonKexBeforeInitialKexInit) &&
            right.evaluate(callbacks, strictKexEnabled, nonKexBeforeInitialKexInit)

        override fun renderTla() = "(${left.renderTla()}) /\\ (${right.renderTla()})"
    }
}

internal operator fun SshFormalGuard.not(): SshFormalGuard = SshFormalGuard.Not(this)

internal infix fun SshFormalGuard.and(other: SshFormalGuard): SshFormalGuard = SshFormalGuard.And(this, other)

internal data class SshFormalTransitionMeta(
    val id: SshTransitionId,
    val eventClass: KClass<out Event>,
    val targetStateName: String?,
    val targetIsHistory: Boolean,
    val guard: SshFormalGuard,
    val origins: Set<SshEventOrigin>,
    val effects: Set<SshEffect>,
    val channelOperationEvent: SshChannelEventId?,
) : MetaInfo {
    init {
        require(origins.isNotEmpty()) { "Formal transition ${id.name} must have an origin" }
        require(!targetIsHistory || targetStateName != null) {
            "Formal transition ${id.name} has a history target without a state name"
        }
    }

    val eventName: String
        get() = requireNotNull(eventClass.qualifiedName)
            .substringAfter(".SshEvent.")
}

internal data class SshFormalState(
    val name: String,
    val parentName: String?,
    val initialChildName: String?,
    val isFinal: Boolean,
    val isHistory: Boolean,
)

internal data class SshFormalTransition(
    val sourceStateNames: Set<String>,
    val meta: SshFormalTransitionMeta,
)

internal data class SshStateMachineFormalModel(
    val initialStateName: String,
    val states: List<SshFormalState>,
    val transitions: List<SshFormalTransition>,
    val channelModel: SshChannelFormalModel,
) {
    private data class FormalVariable(
        val name: String,
        val initialValue: String,
        val renderNext: (SshFormalTransitionMeta) -> String,
    )

    private val stateByName = states.associateBy(SshFormalState::name)
    private val leafStateNames = states
        .filterNot { it.isHistory }
        .filter { state -> states.none { it.parentName == state.name && !it.isHistory } }
        .mapTo(sortedSetOf(), SshFormalState::name)

    init {
        require(states.map(SshFormalState::name).distinct().size == states.size) {
            "Formal state names must be unique"
        }
        require(transitions.map { it.meta.id }.distinct().size == transitions.size) {
            "Formal transition IDs must be unique"
        }
        require(initialStateName in leafStateNames) { "Initial state $initialStateName is not a leaf state" }
        require(transitions.size == SshTransitionId.entries.size) {
            "Expected ${SshTransitionId.entries.size} formal transitions, found ${transitions.size}"
        }
        val generatedConnectionOperations = transitions.mapNotNull { it.meta.channelOperationEvent }.toSet()
        val declaredConnectionOperations = channelModel.operations
            .filter { it.scope == SshChannelOperationScope.CONNECTION_TRANSITION }
            .mapTo(mutableSetOf(), SshChannelFormalOperation::eventId)
        require(generatedConnectionOperations == declaredConnectionOperations) {
            "Connection transitions $generatedConnectionOperations do not match channel operations $declaredConnectionOperations"
        }
        transitions.filter { it.meta.channelOperationEvent != null }.forEach { transition ->
            val channelEvent = requireNotNull(transition.meta.channelOperationEvent)
            val channelOrigin = channelModel.operations.first { it.eventId == channelEvent }.origin
            val expectedOrigin = channelOrigin.connectionOrigin
            require(transition.meta.origins == setOf(expectedOrigin)) {
                "Connection transition ${transition.meta.id} has origins ${transition.meta.origins}, " +
                    "but channel event $channelEvent requires $expectedOrigin"
            }
        }
    }

    fun renderTla(moduleName: String = GENERATED_MODULE_NAME): String {
        val variables = formalVariables()
        val body = buildString {
            appendLine("EXTENDS Naturals")
            appendLine()
            appendLine("CONSTANTS MaxChannels, EnableHostileEnvironment, AdversaryOwnsHostKey, EnforceKexProofVerification")
            appendLine()
            appendLine("ChannelIDs == 1..MaxChannels")
            appendLine("ChannelAttemptIDs == 0..(MaxChannels + 1)")
            appendLine()
            appendLine("VARIABLES ${variables.joinToString(", ", transform = FormalVariable::name)}")
            appendLine()
            appendLine("vars == <<${variables.joinToString(", ", transform = FormalVariable::name)}>>")
            appendLine()
            appendLine("States == ${renderSet(leafStateNames)}")
            appendLine("PostAuthenticatedStates == ${renderSet(descendantLeaves(POST_AUTHENTICATED_STATE))}")
            appendLine("KexStates == ${renderSet(KEX_STATE_NAMES)}")
            val eventNames = transitions.mapTo(sortedSetOf()) { it.meta.eventName }.apply {
                add("HostilePacketRejected")
            }
            appendLine("Events == ${renderSet(eventNames)}")
            appendLine("Origins == ${renderSet(SshEventOrigin.entries.mapTo(sortedSetOf()) { it.tlaName })}")
            appendLine("Effects == ${renderSet(SshEffect.entries.mapTo(sortedSetOf()) { it.tlaName })}")
            appendLine("PacketClasses == ${renderSet(SshPacketClass.entries.mapTo(sortedSetOf()) { it.tlaName })}")
            appendLine("PacketDispositions == {\"None\", \"Client\", \"Accepted\", \"Unimplemented\", \"Disconnected\"}")
            appendChannelDefinitions()
            appendLine()
            appendLine("Init ==")
            variables.forEach { variable ->
                appendLine("    /\\ ${variable.name} = ${variable.initialValue}")
            }
            appendLine()
            transitions.sortedBy { it.meta.id.name }.forEach { transition ->
                appendTransition(transition, variables)
                appendLine()
            }
            appendPacketTransitionEnabled()
            appendLine()
            appendRejectHostilePacket(variables)
            appendLine()
            appendHostileEnvironmentNext(variables)
            appendLine()
            appendLine("ClientNext ==")
            transitions.sortedBy { it.meta.id.name }.forEach { transition ->
                appendLine("    \\/ ${transition.meta.id.name}")
            }
            appendLine("    \\/ AttemptChannelOperation")
            appendLine("    \\/ RejectHostilePacket")
            appendLine()
            appendLine("Next == ClientNext \\/ HostileEnvironmentNext")
            appendLine()
            appendLine("Spec == Init /\\ [][Next]_vars")
        }
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(body.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        return buildString {
            appendLine("---- MODULE $moduleName ----")
            appendLine("\\* Generated from SshClientStateMachine. Do not edit.")
            appendLine("\\* Model SHA-256: $fingerprint")
            appendLine("\\* Lifecycle states: ${leafStateNames.size}; transitions: ${transitions.size}.")
            appendLine("\\* TLC distinct states count full variable valuations, not lifecycle nodes.")
            append(body)
            appendLine("====")
        }
    }

    private fun StringBuilder.appendTransition(
        transition: SshFormalTransition,
        variables: List<FormalVariable>,
    ) {
        val meta = transition.meta
        appendLine("${meta.id.name} ==")
        appendLine("    /\\ state \\in ${renderSet(transition.sourceStateNames)}")
        if (meta.guard != SshFormalGuard.Always) {
            appendLine("    /\\ ${meta.guard.renderTla()}")
        }
        val packets = packetClasses(meta)
        if (packets.isNotEmpty()) {
            appendLine("    /\\ (inboundPacket = \"None\"")
            appendLine("        \\/ /\\ inboundPacket \\in ${renderSet(packets.map { it.tlaName })}")
            packetSecurityGuards(meta).forEach { guard ->
                appendLine("              /\\ $guard")
            }
            appendLine("       )")
        }
        if (meta.id in NEW_KEYS_TRANSITIONS) {
            appendLine("    /\\ (~EnforceKexProofVerification \\/ hostKeyPossessionVerified)")
            appendLine("    /\\ (~EnforceKexProofVerification \\/ transcriptVerified)")
        }
        variables.forEach { variable ->
            appendLine("    /\\ ${variable.renderNext(meta)}")
        }
    }

    private fun formalVariables(): List<FormalVariable> = listOf(
        variable("state", quote(initialStateName), ::renderTarget),
        variable("previousState", quote(initialStateName)) { "state" },
        variable("history", quote(initialPostAuthenticatedState()), ::renderHistoryUpdate),
        variable("event", quote("None")) { quote(it.eventName) },
        FormalVariable("origin", quote(SshEventOrigin.INTERNAL.tlaName)) { meta ->
            if (meta.origins.size == 1) {
                "origin' = ${quote(meta.origins.single().tlaName)}"
            } else {
                "origin' \\in ${renderSet(meta.origins.mapTo(sortedSetOf()) { it.tlaName })}"
            }
        },
        variable("packetWasParsed", "FALSE") { "(origin' = ${quote(SshEventOrigin.PARSED_PACKET.tlaName)})" },
        variable("effects", "{}", ::renderEffectsUpdate),
        variable("rekeying", "FALSE", ::renderRekeyingUpdate),
        FormalVariable("strictKex", "FALSE") { meta ->
            when {
                SshEffect.ENABLE_STRICT_KEX in meta.effects -> "strictKex' = TRUE"
                SshEffect.NEGOTIATE_NON_STRICT_KEX in meta.effects -> "strictKex' = FALSE"
                else -> "strictKex' = strictKex"
            }
        },
        variable("nonKexBeforeInitialKexInit", "FALSE", ::renderNonKexBeforeInitialKexInitUpdate),
        variable("authenticationEstablished", "FALSE", ::renderAuthenticationEstablishedUpdate),
        variable("initialNewKeysActive", "FALSE", ::renderInitialNewKeysActiveUpdate),
        variable("authRequestPending", "FALSE", ::renderAuthRequestPendingUpdate),
        variable("previousAuthRequestPending", "FALSE") { "authRequestPending" },
        FormalVariable("inboundPacket", quote("None")) { meta ->
            if (packetClasses(meta).isEmpty()) "inboundPacket' = inboundPacket" else "inboundPacket' = \"None\""
        },
        FormalVariable("lastInboundPacket", quote("None")) { meta ->
            if (packetClasses(meta).isEmpty()) "lastInboundPacket' = lastInboundPacket" else "lastInboundPacket' = inboundPacket"
        },
        FormalVariable("inboundTranscriptMatches", "FALSE") { meta ->
            "inboundTranscriptMatches' = inboundTranscriptMatches"
        },
        FormalVariable("inboundHostSignatureValid", "FALSE") { meta ->
            "inboundHostSignatureValid' = inboundHostSignatureValid"
        },
        FormalVariable("inboundTransportValid", "FALSE") { meta ->
            "inboundTransportValid' = inboundTransportValid"
        },
        variable("hostKeyPossessionVerified", "FALSE", ::renderHostKeyPossessionVerifiedUpdate),
        variable("transcriptVerified", "FALSE", ::renderTranscriptVerifiedUpdate),
        variable("transportKeysVerified", "FALSE", ::renderTransportKeysVerifiedUpdate),
        FormalVariable("lastPacketDisposition", quote("None")) { meta ->
            if (packetClasses(meta).isEmpty()) {
                "lastPacketDisposition' = \"Client\""
            } else {
                "lastPacketDisposition' = IF inboundPacket = \"None\" THEN \"Client\" ELSE \"Accepted\""
            }
        },
        variable("previousChannels", "[c \\in ChannelIDs |-> \"Unallocated\"]") { "channels" },
        FormalVariable("activeChannel", "0") { meta ->
            val operation = meta.channelOperationEvent
            if (operation == null) {
                "activeChannel' = 0"
            } else {
                "activeChannel' \\in ChannelIDs /\\ " +
                    "ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], ${quote(operation.tlaName)})"
            }
        },
        variable("channelEvent", quote("None")) { quote(it.channelOperationEvent?.tlaName ?: "None") },
        FormalVariable("channelOrigin", quote("None")) { meta ->
            val operation = meta.channelOperationEvent
            if (operation == null) "channelOrigin' = \"None\"" else "channelOrigin' = ChannelOriginFor(${quote(operation.tlaName)})"
        },
        FormalVariable("channels", "[c \\in ChannelIDs |-> \"Unallocated\"]") { meta ->
            when {
                SshEffect.DISCONNECT in meta.effects ->
                    "channels' = [c \\in ChannelIDs |-> IF channels[c] = \"Unallocated\" THEN \"Unallocated\" ELSE \"CLOSED\"]"

                meta.channelOperationEvent != null ->
                    "channels' = [channels EXCEPT ![activeChannel'] = " +
                        "ChannelTransitionTarget(channels[activeChannel'], ${quote(meta.channelOperationEvent.tlaName)})]"

                else -> "channels' = channels"
            }
        },
        FormalVariable("channelEffects", "{}") { meta ->
            val operation = meta.channelOperationEvent
            if (operation == null) {
                "channelEffects' = {}"
            } else {
                "channelEffects' = ChannelEffectsFor(channels[activeChannel'], ${quote(operation.tlaName)})"
            }
        },
    )

    private fun StringBuilder.appendChannelDefinitions() {
        val operations = channelModel.operations
            .filter { it.scope != SshChannelOperationScope.CONNECTION_TEARDOWN }
            .sortedWith(compareBy(SshChannelFormalOperation::sourceStateName, SshChannelFormalOperation::eventName))
        val attemptedOperations = operations.filter { it.scope == SshChannelOperationScope.CHANNEL_ATTEMPT }
        val channelStates = channelModel.states.mapTo(sortedSetOf()) { it.name }.apply {
            add(channelModel.unallocatedStateName)
        }
        val channelEvents = operations.mapTo(sortedSetOf(), SshChannelFormalOperation::eventName)
        val channelAttemptEvents = attemptedOperations.mapTo(sortedSetOf(), SshChannelFormalOperation::eventName)
        val channelEffects = SshChannelEffect.entries.mapTo(sortedSetOf()) { it.name }
        val authenticationRequired = operations.filter(SshChannelFormalOperation::requiresAuthenticatedConnection)

        appendLine()
        appendLine("ChannelStates == ${renderSet(channelStates)}")
        appendLine("ChannelEvents == ${renderSet(channelEvents)}")
        appendLine("ChannelAttemptEvents == ${renderSet(channelAttemptEvents)}")
        appendLine("ChannelEffectSet == ${renderSet(channelEffects)}")
        appendLine("ChannelOrigins == ${renderSet(SshChannelEventOrigin.entries.mapTo(sortedSetOf()) { it.tlaName })}")
        appendLine("ChannelTransitions == {")
        operations.forEachIndexed { index, operation ->
            val suffix = if (index == operations.lastIndex) "" else ","
            appendLine("    <<${quote(operation.sourceStateName)}, ${quote(operation.eventName)}, ${quote(operation.targetStateName)}>>$suffix")
        }
        appendLine("}")
        appendLine("ChannelAuthenticationRequired == {")
        authenticationRequired.forEachIndexed { index, operation ->
            val suffix = if (index == authenticationRequired.lastIndex) "" else ","
            appendLine("    <<${quote(operation.sourceStateName)}, ${quote(operation.eventName)}>>$suffix")
        }
        appendLine("}")
        appendLine()
        appendLine("ChannelTransitionDefined(channelState, operation) ==")
        appendLine("    \\E target \\in ChannelStates : <<channelState, operation, target>> \\in ChannelTransitions")
        appendLine()
        appendLine("ChannelTransitionTarget(channelState, operation) ==")
        appendLine("    CHOOSE target \\in ChannelStates : <<channelState, operation, target>> \\in ChannelTransitions")
        appendLine()
        appendLine("ChannelEffectsFor(channelState, operation) ==")
        operations.forEachIndexed { index, operation ->
            val prefix = if (index == 0) "    CASE " else "      [] "
            appendLine(
                "$prefix/\\ channelState = ${quote(operation.sourceStateName)} /\\ operation = ${quote(operation.eventName)} -> " +
                    renderSet(operation.effects.map { it.name }),
            )
        }
        appendLine("      [] OTHER -> ${renderSet(channelModel.rejectedOperationEffects.map { it.name })}")
        appendLine()
        appendLine("ChannelOriginFor(operation) ==")
        operations.distinctBy(SshChannelFormalOperation::eventId).forEachIndexed { index, operation ->
            val prefix = if (index == 0) "    CASE " else "      [] "
            appendLine("$prefix operation = ${quote(operation.eventName)} -> ${quote(operation.origin.tlaName)}")
        }
        appendLine("      [] OTHER -> \"None\"")
        appendLine()
        appendLine("ChannelOperationAllowed(isAuthenticated, connectionState, channelState, operation) ==")
        appendLine("    /\\ ChannelTransitionDefined(channelState, operation)")
        appendLine("    /\\ connectionState # \"Disconnected\"")
        appendLine("    /\\ (<<channelState, operation>> \\notin ChannelAuthenticationRequired")
        appendLine("        \\/ isAuthenticated)")
        appendLine()
        appendLine("AttemptChannelOperation ==")
        appendLine("    /\\ activeChannel' \\in ChannelAttemptIDs")
        appendLine("    /\\ channelEvent' \\in ChannelAttemptEvents")
        appendLine("    /\\ channelOrigin' = ChannelOriginFor(channelEvent')")
        appendLine("    /\\ previousChannels' = channels")
        appendLine("    /\\ IF activeChannel' \\in ChannelIDs")
        appendLine("          /\\ ChannelOperationAllowed(authenticationEstablished, state, channels[activeChannel'], channelEvent')")
        appendLine("       THEN")
        appendLine("          /\\ channels' = [channels EXCEPT ![activeChannel'] = ChannelTransitionTarget(channels[activeChannel'], channelEvent')]")
        appendLine("          /\\ channelEffects' = ChannelEffectsFor(channels[activeChannel'], channelEvent')")
        appendLine("       ELSE")
        appendLine("          /\\ channels' = channels")
        appendLine(
            "          /\\ channelEffects' = ${renderSet(channelModel.rejectedOperationEffects.map { it.name })}",
        )
        val globalVariableNames = formalVariables()
            .map(FormalVariable::name)
            .filterNot { it in CHANNEL_VARIABLE_NAMES }
        appendLine("    /\\ UNCHANGED <<${globalVariableNames.joinToString()}>>")
    }

    private fun variable(
        name: String,
        initialValue: String,
        nextValue: (SshFormalTransitionMeta) -> String,
    ) = FormalVariable(name, initialValue) { meta -> "$name' = ${nextValue(meta)}" }

    private fun renderTarget(meta: SshFormalTransitionMeta): String {
        val targetName = meta.targetStateName ?: return "state"
        if (meta.targetIsHistory) return "history"
        return quote(resolveInitialLeaf(targetName))
    }

    private fun renderHistoryUpdate(meta: SshFormalTransitionMeta): String = if (SshEffect.REKEY_STARTED in meta.effects) "state" else "history"

    private fun renderRekeyingUpdate(meta: SshFormalTransitionMeta): String = when {
        SshEffect.REKEY_STARTED in meta.effects -> "TRUE"
        SshEffect.REKEY_COMPLETE in meta.effects -> "FALSE"
        SshEffect.DISCONNECT in meta.effects -> "FALSE"
        else -> "rekeying"
    }

    private fun renderEffectsUpdate(meta: SshFormalTransitionMeta): String {
        val resetEffects = meta.effects.intersect(STRICT_KEX_SEQUENCE_RESET_EFFECTS)
        val regularEffects = meta.effects - resetEffects
        val renderedRegularEffects = renderSet(regularEffects.mapTo(sortedSetOf()) { it.tlaName })
        if (resetEffects.isEmpty()) return renderedRegularEffects

        val renderedStrictEffects = renderSet(meta.effects.mapTo(sortedSetOf()) { it.tlaName })
        return "IF strictKex THEN $renderedStrictEffects ELSE $renderedRegularEffects"
    }

    private fun renderAuthenticationEstablishedUpdate(meta: SshFormalTransitionMeta): String = if (SshEffect.AUTHENTICATION_SUCCESS in meta.effects) "TRUE" else "authenticationEstablished"

    private fun renderNonKexBeforeInitialKexInitUpdate(meta: SshFormalTransitionMeta): String = if (SshEffect.RECORD_NON_KEX_BEFORE_INITIAL_KEX_INIT in meta.effects) {
        "TRUE"
    } else if (SshEffect.CLEAR_NON_KEX_BEFORE_INITIAL_KEX_INIT in meta.effects) {
        "FALSE"
    } else {
        "nonKexBeforeInitialKexInit"
    }

    private fun renderInitialNewKeysActiveUpdate(meta: SshFormalTransitionMeta): String = if (SshEffect.ACTIVATE_ENCRYPTION in meta.effects) "TRUE" else "initialNewKeysActive"

    private fun renderAuthRequestPendingUpdate(meta: SshFormalTransitionMeta): String = when {
        SshEffect.SEND_USERAUTH_REQUEST in meta.effects -> "TRUE"
        SshEffect.DISCONNECT in meta.effects -> "FALSE"
        meta.id in AUTH_REQUEST_RESPONSE_TRANSITIONS -> "FALSE"
        else -> "authRequestPending"
    }

    private fun renderHostKeyPossessionVerifiedUpdate(meta: SshFormalTransitionMeta): String = when {
        meta.id in KEX_INIT_TRANSITIONS -> "FALSE"
        meta.id in KEX_REPLY_TRANSITIONS -> "TRUE"
        SshEffect.DISCONNECT in meta.effects -> "FALSE"
        else -> "hostKeyPossessionVerified"
    }

    private fun renderTranscriptVerifiedUpdate(meta: SshFormalTransitionMeta): String = when {
        meta.id in KEX_INIT_TRANSITIONS -> "FALSE"
        meta.id in KEX_REPLY_TRANSITIONS -> "TRUE"
        SshEffect.DISCONNECT in meta.effects -> "FALSE"
        else -> "transcriptVerified"
    }

    private fun renderTransportKeysVerifiedUpdate(meta: SshFormalTransitionMeta): String = when {
        meta.id in NEW_KEYS_TRANSITIONS -> "TRUE"
        SshEffect.DISCONNECT in meta.effects -> "FALSE"
        else -> "transportKeysVerified"
    }

    private fun packetClasses(meta: SshFormalTransitionMeta): Set<SshPacketClass> = when (meta.id) {
        SshTransitionId.RECEIVE_INITIAL_STRICT_KEX_INIT,
        SshTransitionId.RECEIVE_INITIAL_NON_STRICT_KEX_INIT,
        SshTransitionId.RECEIVE_REKEY_KEX_INIT,
        SshTransitionId.REJECT_STRICT_KEX_INIT_NOT_FIRST,
        SshTransitionId.UNEXPECTED_KEX_INIT_WAIT_KEX,
        SshTransitionId.UNEXPECTED_KEX_INIT_WAIT_KEX_DH_GEX_INIT,
        SshTransitionId.UNEXPECTED_KEX_INIT_WAIT_NEW_KEYS,
        -> setOf(SshPacketClass.KEX_INIT)

        SshTransitionId.RECEIVE_KEX_DH_REPLY,
        SshTransitionId.RECEIVE_KEX_ECDH_REPLY,
        SshTransitionId.RECEIVE_KEX_DH_GEX_REPLY,
        -> setOf(SshPacketClass.KEX_REPLY)

        SshTransitionId.RECEIVE_KEX_DH_GEX_GROUP -> setOf(SshPacketClass.KEX_GEX_GROUP)

        SshTransitionId.RECEIVE_INITIAL_NEW_KEYS,
        SshTransitionId.RECEIVE_REKEY_NEW_KEYS,
        -> setOf(SshPacketClass.NEW_KEYS)

        SshTransitionId.RECEIVE_SERVICE_ACCEPT -> setOf(SshPacketClass.SERVICE_ACCEPT)

        SshTransitionId.AUTHENTICATION_SUCCESS -> setOf(SshPacketClass.USERAUTH_SUCCESS)

        SshTransitionId.AUTHENTICATION_FAILURE -> setOf(SshPacketClass.USERAUTH_FAILURE)

        SshTransitionId.RECEIVE_USERAUTH_INFO_REQUEST,
        SshTransitionId.AUTHORIZE_AUTHENTICATION_PACKET,
        -> setOf(SshPacketClass.USERAUTH_METHOD_SPECIFIC)

        SshTransitionId.RECEIVE_USERAUTH_BANNER_READY,
        SshTransitionId.RECEIVE_USERAUTH_BANNER_AUTHENTICATING,
        -> setOf(SshPacketClass.USERAUTH_BANNER)

        SshTransitionId.AUTHORIZE_SERVICE_EXT_INFO,
        SshTransitionId.AUTHORIZE_POST_AUTH_EXT_INFO,
        -> setOf(SshPacketClass.EXT_INFO)

        SshTransitionId.AUTHORIZE_CONNECTION_PACKET -> setOf(SshPacketClass.CONNECTION_PACKET)

        SshTransitionId.AUTHORIZE_AUTHENTICATED_PACKET -> setOf(
            SshPacketClass.CONNECTION_PACKET,
            SshPacketClass.CLIENT_CONNECTION_PACKET,
        )

        SshTransitionId.RECEIVE_GLOBAL_REQUEST -> setOf(SshPacketClass.GLOBAL_REQUEST)

        SshTransitionId.RECEIVE_CHANNEL_OPEN_CONFIRMATION,
        SshTransitionId.RECEIVE_CHANNEL_OPEN_FAILURE,
        -> setOf(SshPacketClass.CHANNEL_OPEN_REPLY)

        SshTransitionId.RECEIVE_CHANNEL_SUCCESS,
        SshTransitionId.RECEIVE_CHANNEL_FAILURE,
        -> setOf(SshPacketClass.CHANNEL_REQUEST_REPLY)

        SshTransitionId.RECEIVE_DEBUG -> setOf(SshPacketClass.DEBUG)

        SshTransitionId.RECEIVE_IGNORE -> setOf(SshPacketClass.IGNORE)

        SshTransitionId.DISCONNECT -> setOf(SshPacketClass.DISCONNECT)

        else -> emptySet()
    }

    private fun packetSecurityGuards(meta: SshFormalTransitionMeta): List<String> {
        val packets = packetClasses(meta)
        if (packets.isEmpty()) return emptyList()
        return when {
            meta.id in KEX_REPLY_TRANSITIONS -> listOf(
                "(~EnforceKexProofVerification \\/ inboundHostSignatureValid)",
                "(~EnforceKexProofVerification \\/ inboundTranscriptMatches)",
                "(~initialNewKeysActive \\/ inboundTransportValid)",
            )

            packets.any { it in PRE_NEW_KEYS_PACKET_CLASSES } ->
                listOf("(~initialNewKeysActive \\/ inboundTransportValid)")

            else -> listOf("inboundTransportValid")
        }
    }

    private fun StringBuilder.appendPacketTransitionEnabled() {
        appendLine("PacketTransitionEnabled ==")
        transitions
            .filter { packetClasses(it.meta).isNotEmpty() }
            .sortedBy { it.meta.id.name }
            .forEach { transition ->
                val meta = transition.meta
                appendLine("    \\/ /\\ state \\in ${renderSet(transition.sourceStateNames)}")
                appendLine("       /\\ inboundPacket \\in ${renderSet(packetClasses(meta).map { it.tlaName })}")
                if (meta.guard != SshFormalGuard.Always) {
                    appendLine("       /\\ ${meta.guard.renderTla()}")
                }
                packetSecurityGuards(meta).forEach { appendLine("       /\\ $it") }
                if (meta.id in NEW_KEYS_TRANSITIONS) {
                    appendLine("       /\\ (~EnforceKexProofVerification \\/ hostKeyPossessionVerified)")
                    appendLine("       /\\ (~EnforceKexProofVerification \\/ transcriptVerified)")
                }
            }
    }

    private fun StringBuilder.appendRejectHostilePacket(variables: List<FormalVariable>) {
        appendLine("HostilePacketFatal ==")
        appendLine("    \\/ /\\ strictKex /\\ ~rekeying /\\ state \\in KexStates")
        appendLine("       /\\ ~PacketTransitionEnabled")
        appendLine("    \\/ /\\ inboundPacket = \"KexInit\"")
        appendLine("       /\\ state \\in {\"WaitKex\", \"WaitKexDhGexInit\", \"WaitNewKeys\"}")
        appendLine("    \\/ /\\ inboundPacket = \"KexReply\"")
        appendLine("       /\\ (~inboundHostSignatureValid \\/ ~inboundTranscriptMatches)")
        appendLine("    \\/ /\\ initialNewKeysActive /\\ ~inboundTransportValid")
        appendLine()
        appendLine("RejectHostilePacket ==")
        appendLine("    /\\ inboundPacket # \"None\"")
        appendLine("    /\\ ~PacketTransitionEnabled")
        variables.forEach { variable ->
            appendLine("    /\\ ${renderRejectedPacketUpdate(variable.name)}")
        }
    }

    private fun renderRejectedPacketUpdate(name: String): String = when (name) {
        "state" -> "state' = IF HostilePacketFatal THEN \"Disconnected\" ELSE state"
        "previousState" -> "previousState' = state"
        "event" -> "event' = \"HostilePacketRejected\""
        "origin" -> "origin' = \"ParsedPacket\""
        "packetWasParsed" -> "packetWasParsed' = TRUE"
        "effects" -> "effects' = IF HostilePacketFatal THEN {\"Disconnect\", \"SendProtocolError\"} ELSE {\"SendUnimplemented\"}"
        "rekeying" -> "rekeying' = IF HostilePacketFatal THEN FALSE ELSE rekeying"
        "authenticationEstablished" -> "authenticationEstablished' = authenticationEstablished"
        "authRequestPending" -> "authRequestPending' = IF HostilePacketFatal THEN FALSE ELSE authRequestPending"
        "previousAuthRequestPending" -> "previousAuthRequestPending' = authRequestPending"
        "inboundPacket" -> "inboundPacket' = \"None\""
        "lastInboundPacket" -> "lastInboundPacket' = inboundPacket"
        "inboundTranscriptMatches" -> "inboundTranscriptMatches' = inboundTranscriptMatches"
        "inboundHostSignatureValid" -> "inboundHostSignatureValid' = inboundHostSignatureValid"
        "inboundTransportValid" -> "inboundTransportValid' = inboundTransportValid"
        "hostKeyPossessionVerified" -> "hostKeyPossessionVerified' = IF HostilePacketFatal THEN FALSE ELSE hostKeyPossessionVerified"
        "transcriptVerified" -> "transcriptVerified' = IF HostilePacketFatal THEN FALSE ELSE transcriptVerified"
        "transportKeysVerified" -> "transportKeysVerified' = IF HostilePacketFatal THEN FALSE ELSE transportKeysVerified"
        "lastPacketDisposition" -> "lastPacketDisposition' = IF HostilePacketFatal THEN \"Disconnected\" ELSE \"Unimplemented\""
        "previousChannels" -> "previousChannels' = channels"
        "activeChannel" -> "activeChannel' = 0"
        "channelEvent" -> "channelEvent' = \"None\""
        "channelOrigin" -> "channelOrigin' = \"None\""
        "channels" -> "channels' = IF HostilePacketFatal THEN [c \\in ChannelIDs |-> IF channels[c] = \"Unallocated\" THEN \"Unallocated\" ELSE \"CLOSED\"] ELSE channels"
        "channelEffects" -> "channelEffects' = {}"
        else -> "$name' = $name"
    }

    private fun StringBuilder.appendHostileEnvironmentNext(variables: List<FormalVariable>) {
        appendLine("HostileEnvironmentNext ==")
        appendLine("    /\\ EnableHostileEnvironment")
        appendLine("    /\\ inboundPacket = \"None\"")
        appendLine("    /\\ inboundPacket' \\in PacketClasses")
        appendLine("    /\\ inboundTranscriptMatches' \\in BOOLEAN")
        appendLine("    /\\ inboundHostSignatureValid' \\in BOOLEAN")
        appendLine("    /\\ (inboundHostSignatureValid' => AdversaryOwnsHostKey)")
        appendLine("    /\\ inboundTransportValid' \\in BOOLEAN")
        appendLine("    /\\ (inboundTransportValid' => AdversaryOwnsHostKey /\\ transportKeysVerified)")
        val unchanged = variables.map(FormalVariable::name).filterNot { it in HOSTILE_PACKET_VARIABLE_NAMES }
        appendLine("    /\\ UNCHANGED <<${unchanged.joinToString()}>>")
    }

    private fun initialPostAuthenticatedState() = resolveInitialLeaf(POST_AUTHENTICATED_STATE)

    private fun resolveInitialLeaf(stateName: String): String {
        val state = requireNotNull(stateByName[stateName]) { "Unknown formal state $stateName" }
        if (state.isHistory) {
            error("History state $stateName must be represented as a history target")
        }
        val initialChild = state.initialChildName ?: return state.name
        return resolveInitialLeaf(initialChild)
    }

    private fun descendantLeaves(stateName: String): Set<String> {
        require(stateName in stateByName) { "Unknown formal state $stateName" }
        val children = states.filter { it.parentName == stateName && !it.isHistory }
        if (children.isEmpty()) return setOf(stateName)
        return children.flatMapTo(sortedSetOf()) { descendantLeaves(it.name) }
    }

    private fun renderSet(values: Collection<String>): String = values
        .joinToString(prefix = "{", postfix = "}") { quote(it) }

    private fun quote(value: String) = "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""

    private val SshEventOrigin.tlaName: String
        get() = name.lowercase().split('_').joinToString("") { it.replaceFirstChar(Char::uppercase) }

    private val SshEffect.tlaName: String
        get() = name.lowercase().split('_').joinToString("") { it.replaceFirstChar(Char::uppercase) }

    companion object {
        const val GENERATED_MODULE_NAME = "SshClientStateMachineGenerated"
        private const val POST_AUTHENTICATED_STATE = "PostAuthenticated"
        private val KEX_STATE_NAMES = sortedSetOf("WaitKexInit", "WaitKex", "WaitKexDhGexInit", "WaitNewKeys")
        private val AUTH_REQUEST_RESPONSE_TRANSITIONS = setOf(
            SshTransitionId.AUTHENTICATION_SUCCESS,
            SshTransitionId.AUTHENTICATION_FAILURE,
            SshTransitionId.AUTHORIZE_AUTHENTICATION_PACKET,
        )
        private val STRICT_KEX_SEQUENCE_RESET_EFFECTS = setOf(
            SshEffect.RESET_INBOUND_SEQUENCE,
            SshEffect.RESET_OUTBOUND_SEQUENCE,
        )
        private val KEX_INIT_TRANSITIONS = setOf(
            SshTransitionId.RECEIVE_INITIAL_STRICT_KEX_INIT,
            SshTransitionId.RECEIVE_INITIAL_NON_STRICT_KEX_INIT,
            SshTransitionId.RECEIVE_REKEY_KEX_INIT,
        )
        private val KEX_REPLY_TRANSITIONS = setOf(
            SshTransitionId.RECEIVE_KEX_DH_REPLY,
            SshTransitionId.RECEIVE_KEX_ECDH_REPLY,
            SshTransitionId.RECEIVE_KEX_DH_GEX_REPLY,
        )
        private val NEW_KEYS_TRANSITIONS = setOf(
            SshTransitionId.RECEIVE_INITIAL_NEW_KEYS,
            SshTransitionId.RECEIVE_REKEY_NEW_KEYS,
        )
        private val PRE_NEW_KEYS_PACKET_CLASSES = setOf(
            SshPacketClass.KEX_INIT,
            SshPacketClass.KEX_REPLY,
            SshPacketClass.KEX_GEX_GROUP,
            SshPacketClass.NEW_KEYS,
            SshPacketClass.DEBUG,
            SshPacketClass.IGNORE,
            SshPacketClass.DISCONNECT,
        )
        private val HOSTILE_PACKET_VARIABLE_NAMES = setOf(
            "inboundPacket",
            "inboundTranscriptMatches",
            "inboundHostSignatureValid",
            "inboundTransportValid",
        )
        private val CHANNEL_VARIABLE_NAMES = setOf(
            "channels",
            "previousChannels",
            "activeChannel",
            "channelEvent",
            "channelOrigin",
            "channelEffects",
        )
    }
}

private val SshPacketClass.tlaName: String
    get() = name.lowercase().split('_').joinToString("") { it.replaceFirstChar(Char::uppercase) }

private val SshChannelEventOrigin.tlaName: String
    get() = when (this) {
        SshChannelEventOrigin.CONNECTION_CONTROL -> "ConnectionControl"
        SshChannelEventOrigin.LOCAL_COMMAND -> "LocalCommand"
        SshChannelEventOrigin.PARSED_PACKET -> "ParsedPacket"
    }

private val SshChannelEventOrigin.connectionOrigin: SshEventOrigin
    get() = when (this) {
        SshChannelEventOrigin.CONNECTION_CONTROL -> SshEventOrigin.INTERNAL
        SshChannelEventOrigin.LOCAL_COMMAND -> SshEventOrigin.LOCAL_COMMAND
        SshChannelEventOrigin.PARSED_PACKET -> SshEventOrigin.PARSED_PACKET
    }

internal fun StateMachine.toSshFormalModel(): SshStateMachineFormalModel {
    val allStates = collectStates(this)
    val formalStates = allStates
        .filterNot { it === this }
        .map { state ->
            SshFormalState(
                name = state.requireName(),
                parentName = state.parent?.takeUnless { it === this }?.requireName(),
                initialChildName = state.initialState?.requireName(),
                isFinal = state is FinalState,
                isHistory = state is HistoryState,
            )
        }
        .sortedBy(SshFormalState::name)
    val formalStateByName = formalStates.associateBy(SshFormalState::name)
    val leafStates = formalStates
        .filterNot { it.isHistory }
        .filter { state -> formalStates.none { it.parentName == state.name && !it.isHistory } }
        .mapTo(sortedSetOf(), SshFormalState::name)

    fun descendantLeaves(source: IState): Set<String> {
        if (source === this) {
            return leafStates.filterTo(sortedSetOf()) { formalStateByName.getValue(it).isFinal.not() }
        }
        val sourceName = source.requireName()
        val children = formalStates.filter { it.parentName == sourceName && !it.isHistory }
        return if (children.isEmpty()) {
            setOf(sourceName)
        } else {
            children.flatMapTo(sortedSetOf()) { child ->
                val childState = allStates.single { it.name == child.name }
                descendantLeaves(childState)
            }
        }
    }

    val transitions = allStates.flatMap { source ->
        source.transitions.mapNotNull { transition ->
            val meta = transition.metaInfo as? SshFormalTransitionMeta
            if (meta == null && transition.eventMatcher.eventClass == StartEvent::class) {
                return@mapNotNull null
            }
            requireNotNull(meta) {
                "Transition ${transition.name} on ${source.name} has no formal metadata"
            }
            require(transition.name == meta.id.name) {
                "Transition ${transition.name} does not match formal ID ${meta.id.name}"
            }
            SshFormalTransition(
                sourceStateNames = descendantLeaves(source),
                meta = meta,
            )
        }
    }

    return SshStateMachineFormalModel(
        initialStateName = resolveInitialLeaf(requireNotNull(initialState)),
        states = formalStates,
        transitions = transitions,
        channelModel = SshChannelStateMachine(SshChannelState.OPEN).formalModel(),
    )
}

private fun collectStates(root: IState): List<IState> = buildList {
    add(root)
    root.states.sortedBy { it.name }.forEach { addAll(collectStates(it)) }
}

private fun resolveInitialLeaf(state: IState): String {
    require(state !is PseudoState) { "Initial state ${state.name} cannot be a pseudo state" }
    val initialChild = state.initialState ?: return state.requireName()
    return resolveInitialLeaf(initialChild)
}

private fun IState.requireName(): String = requireNotNull(name).also {
    require(it.isNotBlank()) { "Formal state names must not be blank" }
}

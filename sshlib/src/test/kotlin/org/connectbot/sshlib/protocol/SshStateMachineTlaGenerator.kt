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

import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

internal object SshStateMachineTlaGenerator {
    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 1) { "Expected the generated TLA+ output path" }
        val output = Path.of(args.single())
        Files.createDirectories(output.parent)
        Files.writeString(output, createFormalModel().renderTla())
    }
}

class SshStateMachineFormalModelTest {
    @Test
    fun `channel TLA is serialized from typed runtime operations`() {
        val model = createFormalModel()
        val rendered = model.renderTla()

        assertTrue("ChannelTransitions == {" in rendered)
        model.channelModel.operations
            .filter { it.scope != SshChannelOperationScope.CONNECTION_TEARDOWN }
            .forEach { operation ->
                assertTrue(
                    "<<\"${operation.sourceStateName}\", \"${operation.eventName}\", \"${operation.targetStateName}\">>" in rendered,
                )
            }
    }

    @Test
    fun `rejected operation policy is not hard coded by TLA renderer`() {
        val model = createFormalModel()
        val deliberatelyUnsafe = model.copy(
            channelModel = model.channelModel.copy(
                rejectedOperationEffects = setOf(SshChannelEffect.SEND_DATA),
            ),
        )

        assertTrue("channelEffects' = {\"SEND_DATA\"}" in deliberatelyUnsafe.renderTla())
    }

    @Test
    fun `channel authorization uses sticky authentication across rekey`() {
        val rendered = createFormalModel().renderTla()

        assertTrue("ChannelOperationAllowed(authenticationEstablished, state," in rendered)
        assertTrue("ChannelOperationAllowed(isAuthenticated, connectionState, channelState, operation)" in rendered)
        assertTrue("connectionState # \"Disconnected\"" in rendered)
        assertTrue("\\/ isAuthenticated" in rendered)
        assertTrue("connectionState = \"Authenticated\"" !in rendered)
    }

    @Test
    fun `every KStateMachine transition has unique formal metadata`() {
        val model = createFormalModel()

        assertEquals(SshTransitionId.entries.size, model.transitions.size)
        assertEquals(SshTransitionId.entries.toSet(), model.transitions.map { it.meta.id }.toSet())
        assertTrue(model.transitions.all { it.sourceStateNames.isNotEmpty() })
    }

    @Test
    fun `rekey guards are shared by Kotlin execution and TLA generation`() {
        val transitions = createFormalModel().transitions.associateBy { it.meta.id }

        assertEquals(
            "~(rekeying)",
            transitions.getValue(SshTransitionId.RECEIVE_INITIAL_NEW_KEYS).meta.guard.renderTla(),
        )
        assertEquals(
            "rekeying",
            transitions.getValue(SshTransitionId.RECEIVE_REKEY_NEW_KEYS).meta.guard.renderTla(),
        )
        assertTrue(transitions.getValue(SshTransitionId.RECEIVE_REKEY_NEW_KEYS).meta.targetIsHistory)
    }

    @Test
    fun `strict kex negotiation and directional protection are explicit effects`() {
        val transitions = createFormalModel().transitions.associateBy { it.meta.id }

        assertEquals(
            "(~(rekeying)) /\\ (~(nonKexBeforeInitialKexInit))",
            transitions.getValue(SshTransitionId.RECEIVE_INITIAL_STRICT_KEX_INIT).meta.guard.renderTla(),
        )
        assertTrue(
            SshEffect.ENABLE_STRICT_KEX in
                transitions.getValue(SshTransitionId.RECEIVE_INITIAL_STRICT_KEX_INIT).meta.effects,
        )
        assertTrue(
            SshEffect.NEGOTIATE_NON_STRICT_KEX in
                transitions.getValue(SshTransitionId.RECEIVE_INITIAL_NON_STRICT_KEX_INIT).meta.effects,
        )
        assertEquals(
            "rekeying",
            transitions.getValue(SshTransitionId.RECEIVE_REKEY_KEX_INIT).meta.guard.renderTla(),
        )
        assertTrue(
            SshEffect.ENABLE_STRICT_KEX !in
                transitions.getValue(SshTransitionId.RECEIVE_REKEY_KEX_INIT).meta.effects,
        )
        assertTrue(
            SshEffect.ACTIVATE_OUTBOUND_PROTECTION in
                transitions.getValue(SshTransitionId.RECEIVE_KEX_ECDH_REPLY).meta.effects,
        )
        assertTrue(
            SshEffect.RESET_OUTBOUND_SEQUENCE in
                transitions.getValue(SshTransitionId.RECEIVE_KEX_ECDH_REPLY).meta.effects,
        )
        assertTrue(
            SshEffect.ACTIVATE_INBOUND_PROTECTION in
                transitions.getValue(SshTransitionId.RECEIVE_REKEY_NEW_KEYS).meta.effects,
        )
        assertTrue(
            SshEffect.RESET_INBOUND_SEQUENCE in
                transitions.getValue(SshTransitionId.RECEIVE_REKEY_NEW_KEYS).meta.effects,
        )
    }

    @Test
    fun `strict initial kex rejection is declared by runtime transitions`() {
        val transitions = createFormalModel().transitions.associateBy { it.meta.id }
        val rejectionIds = setOf(
            SshTransitionId.REJECT_NON_KEX_WAIT_KEX,
            SshTransitionId.REJECT_NON_KEX_WAIT_KEX_DH_GEX_INIT,
            SshTransitionId.REJECT_NON_KEX_WAIT_NEW_KEYS,
        )

        rejectionIds.forEach { id ->
            val transition = transitions.getValue(id).meta
            assertEquals("(strictKex) /\\ (~(rekeying))", transition.guard.renderTla())
            assertEquals(setOf(SshEffect.SEND_PROTOCOL_ERROR, SshEffect.DISCONNECT), transition.effects)
            assertEquals("Disconnected", transition.targetStateName)
        }

        val firstPacket = transitions.getValue(SshTransitionId.REJECT_STRICT_KEX_INIT_NOT_FIRST).meta
        assertEquals(
            "(~(rekeying)) /\\ (nonKexBeforeInitialKexInit)",
            firstPacket.guard.renderTla(),
        )
        assertEquals(
            setOf(
                SshEffect.RECEIVE_KEX_INIT,
                SshEffect.ENABLE_STRICT_KEX,
                SshEffect.SEND_PROTOCOL_ERROR,
                SshEffect.DISCONNECT,
            ),
            firstPacket.effects,
        )
    }

    @Test
    fun `focused Terrapin model checks strict safety and expects non-strict counterexample`() {
        val model = Files.readString(Path.of("src/test/resources/tla/SshTerrapin.tla"))
        val strictConfig = Files.readString(Path.of("src/test/resources/tla/SshTerrapinStrict.cfg"))
        val nonStrictConfig = Files.readString(Path.of("src/test/resources/tla/SshTerrapinNonStrict.cfg"))

        assertTrue("InjectUnauthenticatedIgnore ==" in model)
        assertTrue("DropExtInfo ==" in model)
        assertTrue("TerrapinSucceeded ==" in model)
        assertTrue("NoTerrapin == ~TerrapinSucceeded" in model)
        assertTrue("StrictKex = TRUE" in strictConfig)
        assertTrue("StrictKex = FALSE" in nonStrictConfig)
        assertTrue("INVARIANT NoTerrapin" in strictConfig)
        assertTrue("INVARIANT NoTerrapin" in nonStrictConfig)

        // Bind SshTerrapin.tla abstractions to SshClientStateMachine formal model declarations
        val transitions = createFormalModel().transitions.associateBy { it.meta.id }
        val strictInit = transitions.getValue(SshTransitionId.RECEIVE_INITIAL_STRICT_KEX_INIT).meta
        assertTrue(SshEffect.ENABLE_STRICT_KEX in strictInit.effects)

        // Sequence number reset on initial KEX completion (modeled in SshTerrapin.CompleteInitialKex)
        val ecdhReply = transitions.getValue(SshTransitionId.RECEIVE_KEX_ECDH_REPLY).meta
        assertTrue(SshEffect.RESET_OUTBOUND_SEQUENCE in ecdhReply.effects)

        // Unauthenticated packet injection abort under strict KEX (modeled in SshTerrapin.InjectUnauthenticatedIgnore)
        val rejectNotFirst = transitions.getValue(SshTransitionId.REJECT_STRICT_KEX_INIT_NOT_FIRST).meta
        assertTrue(SshEffect.DISCONNECT in rejectNotFirst.effects)
    }

    @Test
    fun `authentication requests are explicit formal side effects`() {
        val transitions = createFormalModel().transitions.associateBy { it.meta.id }

        assertEquals(
            setOf(SshEffect.SEND_USERAUTH_REQUEST),
            transitions.getValue(SshTransitionId.BEGIN_AUTHENTICATION).meta.effects,
        )
        assertEquals(
            setOf(SshEffect.SEND_USERAUTH_REQUEST),
            transitions.getValue(SshTransitionId.REPEAT_BEGIN_AUTHENTICATION).meta.effects,
        )
        assertEquals(
            "~(authRequestPending)",
            transitions.getValue(SshTransitionId.BEGIN_AUTHENTICATION).meta.guard.renderTla(),
        )
        assertEquals(
            "~(authRequestPending)",
            transitions.getValue(SshTransitionId.REPEAT_BEGIN_AUTHENTICATION).meta.guard.renderTla(),
        )
    }

    @Test
    fun `unexpected kex init is modeled as fatal from every mid kex state`() {
        val transitions = createFormalModel().transitions
            .filter { it.meta.eventName == "UnexpectedKexInit" }

        assertEquals(
            setOf("WaitKex", "WaitKexDhGexInit", "WaitNewKeys"),
            transitions.flatMapTo(mutableSetOf()) { it.sourceStateNames },
        )
        assertTrue(transitions.all { it.meta.targetStateName == "Disconnected" })
        assertTrue(
            transitions.all {
                it.meta.effects == setOf(SshEffect.SEND_PROTOCOL_ERROR, SshEffect.DISCONNECT)
            },
        )
    }

    @Test
    fun `TLC checks global operations for channel non-interference`() {
        val handwritten = Files.readString(Path.of("src/test/resources/tla/SshClientStateMachine.tla"))
        val config = Files.readString(Path.of("src/test/resources/tla/SshClientStateMachine.cfg"))

        assertTrue("GlobalOperationsPreserveChannels ==" in handwritten)
        assertTrue("GlobalChannelMutationIsDisconnectCascade ==" in handwritten)
        assertTrue("INVARIANT GlobalOperationsPreserveChannels" in config)
        assertTrue("INVARIANT GlobalChannelMutationIsDisconnectCascade" in config)
    }

    @Test
    fun `TLC explores strict and non-strict key exchange`() {
        val rendered = createFormalModel().renderTla()
        val config = Files.readString(Path.of("src/test/resources/tla/SshClientStateMachine.cfg"))

        assertTrue("strictKex' = TRUE" in rendered)
        assertTrue("strictKex' = FALSE" in rendered)
        assertTrue("IF strictKex THEN" in rendered)
        assertTrue("INVARIANT StrictKexProtectionSwitchesResetSequenceNumbers" in config)
        assertTrue("PROPERTY StrictKexIsSticky" in config)
    }

    @Test
    fun `generated model composes client and hostile environment actions`() {
        val rendered = createFormalModel().renderTla()

        assertTrue("PacketClasses ==" in rendered)
        assertTrue("PacketTransitionEnabled ==" in rendered)
        assertTrue("HostileEnvironmentNext ==" in rendered)
        assertTrue("RejectHostilePacket ==" in rendered)
        assertTrue("ClientNext ==" in rendered)
        assertTrue("Next == ClientNext \\/ HostileEnvironmentNext" in rendered)
        assertTrue("hostKeyPossessionVerified" in rendered)
        assertTrue("transcriptVerified" in rendered)
        assertTrue("transportKeysVerified" in rendered)
    }

    @Test
    fun `checked in TLA model matches KStateMachine declaration`() {
        val expected = Files.readString(Path.of("src/test/resources/tla/SshClientStateMachineGenerated.tla"))

        assertEquals(expected, createFormalModel().renderTla())
    }
}

private fun createFormalModel(): SshStateMachineFormalModel {
    val callbacks = Proxy.newProxyInstance(
        SshClientCallbacks::class.java.classLoader,
        arrayOf(SshClientCallbacks::class.java),
    ) { _, method, _ ->
        when {
            method.returnType == Boolean::class.javaPrimitiveType -> false
            method.returnType == Void.TYPE -> null
            else -> Unit
        }
    } as SshClientCallbacks
    return SshClientStateMachine(callbacks).formalModel()
}

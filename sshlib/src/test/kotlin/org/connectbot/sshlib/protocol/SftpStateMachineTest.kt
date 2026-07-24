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

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal object SftpStateMachineTlaGenerator {
    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 1) { "Expected the generated TLA+ output path" }
        val output = Path.of(args.single())
        Files.createDirectories(output.parent)
        val machine = SftpStateMachine()
        val renderer = SftpStateMachineFormalModel(machine.formalModel())
        Files.writeString(output, renderer.renderTla())
    }
}

class SftpStateMachineTest {

    @Test
    fun `formal model captures all transitions`() {
        val machine = SftpStateMachine()
        val formal = machine.formalModel()
        assertEquals(4, formal.states.size)
        assertTrue(SftpState.UNINITIALIZED in formal.states)
        assertTrue(SftpState.WAIT_VERSION in formal.states)
        assertTrue(SftpState.READY in formal.states)
        assertTrue(SftpState.CLOSED in formal.states)
    }

    @Test
    fun `renderTla emits valid module body`() {
        val machine = SftpStateMachine()
        val model = machine.formalModel()
        val renderer = SftpStateMachineFormalModel(model)
        val tla = renderer.renderTla()

        assertTrue("---- MODULE SftpClientStateMachineGenerated ----" in tla)
        assertTrue("CONSTANT MaxHandles, MaxRequests" in tla)
        assertTrue("AllocateHandle ==" in tla)
        assertTrue("ReadFileOp ==" in tla)
        assertTrue("FulfillResponse ==" in tla)
        assertTrue("====" in tla)
    }

    @Test
    fun `renderer requires runtime transitions for modeled operations`() {
        val formal = SftpStateMachine().formalModel()
        val missingRead = formal.copy(
            transitions = formal.transitions.filterNot { it.eventId == SftpEventId.READ_FILE },
        )

        assertFailsWith<IllegalStateException> {
            SftpStateMachineFormalModel(missingRead).renderTla()
        }
    }

    @Test
    fun `renderer generates declarations initialization and updates from formal variables`() {
        val tla = SftpStateMachineFormalModel(SftpStateMachine().formalModel()).renderTla()
        val variables = tla.lineSequence()
            .single { it.startsWith("VARIABLES ") }
            .removePrefix("VARIABLES ")
            .split(", ")
        val init = tla.substringAfter("Init ==\n").substringBefore("\n\n")
        val sendInit = tla.substringAfter("SEND_INIT_UNINITIALIZED ==\n").substringBefore("\n\n")

        variables.forEach { variable ->
            assertTrue("/\\ $variable =" in init, "$variable is missing from Init")
            assertTrue("$variable'" in sendInit, "$variable is missing from a generated transition")
        }
        assertTrue("vars == <<${variables.joinToString(", ")}>>" in tla)
    }

    @Test
    fun `request write action is serialized with disconnect`() = runBlocking {
        val machine = SftpStateMachine()
        assertTrue(machine.sendInit { })
        assertTrue(machine.receiveVersion { })
        val writeStarted = CompletableDeferred<Unit>()
        val finishWrite = CompletableDeferred<Unit>()

        val request = async {
            machine.request {
                writeStarted.complete(Unit)
                finishWrite.await()
            }
        }
        writeStarted.await()
        val disconnect = async { machine.disconnect { } }
        yield()

        assertFalse(disconnect.isCompleted)
        finishWrite.complete(Unit)
        assertTrue(request.await())
        assertTrue(disconnect.await())
        assertEquals(SftpState.CLOSED, machine.state)
    }

    @Test
    fun `generated TLA file matches rendered model`() {
        val machine = SftpStateMachine()
        val renderer = SftpStateMachineFormalModel(machine.formalModel())
        val generatedPath = Path.of("src/test/resources/tla/SftpClientStateMachineGenerated.tla")
        if (Files.exists(generatedPath)) {
            val fileContent = Files.readString(generatedPath)
            assertEquals(renderer.renderTla(), fileContent)
        }
    }

    @Test
    fun `enforces response matching in state machine`() = runBlocking {
        val machine = SftpStateMachine()
        assertTrue(machine.sendInit { })
        assertTrue(machine.receiveVersion { })

        // Issue OpenFile -> expect PendingOpen
        assertTrue(machine.openFile { })

        // ReceiveData is declined because no READ is pending
        assertFalse(machine.receiveData { })

        // ReceiveHandle is accepted
        assertTrue(machine.receiveHandle { })

        // Issue ReadFile -> expect PendingRead
        assertTrue(machine.readFile { })

        // ReceiveHandle is declined because no OPEN is pending
        assertFalse(machine.receiveHandle { })

        // ReceiveData is accepted
        assertTrue(machine.receiveData { })
    }
}

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

import java.security.MessageDigest

internal class SftpStateMachineFormalModel(
    val model: SftpFormalModel,
) {
    private data class FormalVariable(
        val name: String,
        val initialValue: String,
        val renderNext: (FormalStep) -> String,
    )

    private data class FormalStep(
        val transition: SftpFormalTransition,
        val handles: String = "handles",
        val activeHandle: String = "activeHandle' = 0",
        val pendingRequests: String = "pendingRequests",
        val activeRequest: String = "activeRequest' = 0",
    )

    fun renderTla(moduleName: String = "SftpClientStateMachineGenerated"): String {
        val states = model.states.mapTo(sortedSetOf()) { it.name }
        val events = model.transitions.mapTo(sortedSetOf()) { it.eventId.tlaName }
        val origins = model.transitions.mapTo(sortedSetOf()) { it.origin.name }
        val effects = model.transitions.flatMapTo(sortedSetOf()) { transition ->
            transition.effects.map(SftpEffect::name)
        }
        val handleStates = SftpHandleState.entries.mapTo(sortedSetOf()) { it.name }
        val variables = formalVariables()

        val sessionTransitions = model.transitions.filter {
            it.eventId in setOf(SftpEventId.SEND_INIT, SftpEventId.RECEIVE_VERSION, SftpEventId.DISCONNECT)
        }
        val openFile = model.transitionFor(SftpEventId.OPEN_FILE)
        val openDir = model.transitionFor(SftpEventId.OPEN_DIR)
        val readFile = model.transitionFor(SftpEventId.READ_FILE)
        val writeFile = model.transitionFor(SftpEventId.WRITE_FILE)
        val readDir = model.transitionFor(SftpEventId.READ_DIR)
        val closeHandle = model.transitionFor(SftpEventId.CLOSE_HANDLE)
        val request = model.transitionFor(SftpEventId.REQUEST)
        val responseTransitions = listOf(
            SftpEventId.RECEIVE_HANDLE,
            SftpEventId.RECEIVE_DATA,
            SftpEventId.RECEIVE_NAME,
            SftpEventId.RECEIVE_STATUS,
            SftpEventId.RECEIVE_ATTRS,
        ).map { model.transitionFor(it) }

        val body = buildString {
            appendLine("EXTENDS Naturals")
            appendLine()
            appendLine("CONSTANT MaxHandles, MaxRequests")
            appendLine()
            appendLine("HandleIDs == 1..MaxHandles")
            appendLine("RequestIDs == 1..MaxRequests")
            appendLine()
            appendLine("VARIABLES ${variables.joinToString(", ", transform = FormalVariable::name)}")
            appendLine()
            appendLine("vars == <<${variables.joinToString(", ", transform = FormalVariable::name)}>>")
            appendLine()
            appendLine("States == ${renderSet(states)}")
            appendLine("Events == ${renderSet(events)}")
            appendLine("Origins == ${renderSet(origins)}")
            appendLine("Effects == ${renderSet(effects)}")
            appendLine("HandleStates == ${renderSet(handleStates)}")
            appendLine()
            appendLine("Init ==")
            variables.forEach { variable ->
                appendLine("    /\\ ${variable.name} = ${variable.initialValue}")
            }
            appendLine()

            sessionTransitions.sortedBy { it.id.name }.forEach { transition ->
                val disconnect = transition.eventId == SftpEventId.DISCONNECT
                appendTransition(
                    transition.id.name,
                    FormalStep(
                        transition = transition,
                        handles = if (disconnect) {
                            "[h \\in HandleIDs |-> IF handles[h] = \"Unallocated\" THEN \"Unallocated\" ELSE \"Closed\"]"
                        } else {
                            "handles"
                        },
                        pendingRequests = if (disconnect) "[r \\in RequestIDs |-> \"None\"]" else "pendingRequests",
                    ),
                    variables,
                )
                appendLine()
            }

            appendTransition(
                "AllocateHandle",
                FormalStep(
                    transition = openFile,
                    handles = "[handles EXCEPT ![activeHandle'] = \"OpenFile\"]",
                    activeHandle = "activeHandle' \\in HandleIDs",
                    pendingRequests = "[pendingRequests EXCEPT ![activeRequest'] = \"PendingOpen\"]",
                    activeRequest = "activeRequest' \\in RequestIDs",
                ),
                variables,
                "handles[activeHandle'] = \"Unallocated\"",
                "pendingRequests[activeRequest'] = \"None\"",
            )
            appendLine()

            appendTransition(
                "AllocateDirHandle",
                FormalStep(
                    transition = openDir,
                    handles = "[handles EXCEPT ![activeHandle'] = \"OpenDir\"]",
                    activeHandle = "activeHandle' \\in HandleIDs",
                    pendingRequests = "[pendingRequests EXCEPT ![activeRequest'] = \"PendingOpen\"]",
                    activeRequest = "activeRequest' \\in RequestIDs",
                ),
                variables,
                "handles[activeHandle'] = \"Unallocated\"",
                "pendingRequests[activeRequest'] = \"None\"",
            )
            appendLine()

            appendTransition(
                "ReadFileOp",
                requestStep(readFile, "PendingRead"),
                variables,
                "handles[activeHandle'] = \"OpenFile\"",
                "pendingRequests[activeRequest'] = \"None\"",
            )
            appendLine()

            appendTransition(
                "WriteFileOp",
                requestStep(writeFile, "PendingWrite"),
                variables,
                "handles[activeHandle'] = \"OpenFile\"",
                "pendingRequests[activeRequest'] = \"None\"",
            )
            appendLine()

            appendTransition(
                "ReadDirOp",
                requestStep(readDir, "PendingReadDir"),
                variables,
                "handles[activeHandle'] = \"OpenDir\"",
                "pendingRequests[activeRequest'] = \"None\"",
            )
            appendLine()

            appendTransition(
                "CloseHandleOp",
                requestStep(
                    transition = closeHandle,
                    pendingState = "PendingClose",
                    handles = "[handles EXCEPT ![activeHandle'] = \"Closed\"]",
                ),
                variables,
                "handles[activeHandle'] \\in {\"OpenFile\", \"OpenDir\"}",
                "pendingRequests[activeRequest'] = \"None\"",
            )
            appendLine()

            appendTransition(
                "RequestOp",
                FormalStep(
                    transition = request,
                    pendingRequests = "[pendingRequests EXCEPT ![activeRequest'] = \"PendingRequest\"]",
                    activeRequest = "activeRequest' \\in RequestIDs",
                ),
                variables,
                "pendingRequests[activeRequest'] = \"None\"",
            )
            appendLine()

            appendLine("FulfillResponse ==")
            responseTransitions.forEach { transition ->
                val step = FormalStep(
                    transition = transition,
                    pendingRequests = "[pendingRequests EXCEPT ![activeRequest'] = \"None\"]",
                    activeRequest = "activeRequest' \\in RequestIDs",
                )
                appendLine("    \\/ /\\ state = ${quote(transition.source.name)}")
                variables.forEach { variable ->
                    appendLine("       /\\ ${variable.renderNext(step)}")
                }
                appendLine("       /\\ pendingRequests[activeRequest'] # \"None\"")
            }
            appendLine()

            appendLine("Next ==")
            sessionTransitions.sortedBy { it.id.name }.forEach { transition ->
                appendLine("    \\/ ${transition.id.name}")
            }
            appendLine("    \\/ AllocateHandle")
            appendLine("    \\/ AllocateDirHandle")
            appendLine("    \\/ ReadFileOp")
            appendLine("    \\/ WriteFileOp")
            appendLine("    \\/ ReadDirOp")
            appendLine("    \\/ CloseHandleOp")
            appendLine("    \\/ RequestOp")
            appendLine("    \\/ FulfillResponse")
            appendLine()
            appendLine("Spec == Init /\\ [][Next]_vars")
        }

        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(body.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        return buildString {
            appendLine("---- MODULE $moduleName ----")
            appendLine("\\* Generated from SftpStateMachine. Do not edit.")
            appendLine("\\* Model SHA-256: $fingerprint")
            append(body)
            appendLine("====")
        }
    }

    private fun StringBuilder.appendTransition(
        name: String,
        step: FormalStep,
        variables: List<FormalVariable>,
        vararg guards: String,
    ) {
        appendLine("$name ==")
        appendLine("    /\\ state = ${quote(step.transition.source.name)}")
        variables.forEach { variable ->
            appendLine("    /\\ ${variable.renderNext(step)}")
        }
        guards.forEach { guard -> appendLine("    /\\ $guard") }
    }

    private fun requestStep(
        transition: SftpFormalTransition,
        pendingState: String,
        handles: String = "handles",
    ) = FormalStep(
        transition = transition,
        handles = handles,
        activeHandle = "activeHandle' \\in HandleIDs",
        pendingRequests = "[pendingRequests EXCEPT ![activeRequest'] = ${quote(pendingState)}]",
        activeRequest = "activeRequest' \\in RequestIDs",
    )

    private fun formalVariables(): List<FormalVariable> = listOf(
        variable("state", quote(SftpState.UNINITIALIZED.name)) { quote(it.transition.target.name) },
        variable("previousState", quote(SftpState.UNINITIALIZED.name)) { "state" },
        variable("event", quote("None")) { quote(it.transition.eventId.tlaName) },
        variable("origin", quote(SftpEventOrigin.LOCAL_COMMAND.name)) { quote(it.transition.origin.name) },
        variable("effects", "{}") { renderSet(it.transition.effects.map(SftpEffect::name)) },
        variable("previousHandles", "[h \\in HandleIDs |-> \"Unallocated\"]") { "handles" },
        FormalVariable("activeHandle", "0", FormalStep::activeHandle),
        variable("handles", "[h \\in HandleIDs |-> \"Unallocated\"]", FormalStep::handles),
        variable("previousPendingRequests", "[r \\in RequestIDs |-> \"None\"]") { "pendingRequests" },
        FormalVariable("activeRequest", "0", FormalStep::activeRequest),
        variable("pendingRequests", "[r \\in RequestIDs |-> \"None\"]", FormalStep::pendingRequests),
    )

    private fun variable(
        name: String,
        initialValue: String,
        nextValue: (FormalStep) -> String,
    ) = FormalVariable(name, initialValue) { step -> "$name' = ${nextValue(step)}" }

    private fun renderSet(values: Collection<String>): String = values
        .toSortedSet()
        .joinToString(prefix = "{", postfix = "}", transform = ::quote)

    private fun quote(value: String) = "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""

    private fun SftpFormalModel.transitionFor(eventId: SftpEventId): SftpFormalTransition = transitions.singleOrNull { it.eventId == eventId }
        ?: error("Expected exactly one SFTP transition for ${eventId.name}")
}

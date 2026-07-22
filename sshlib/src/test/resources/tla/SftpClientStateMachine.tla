---- MODULE SftpClientStateMachine ----
EXTENDS SftpClientStateMachineGenerated

TypeOK ==
    /\ state \in States
    /\ previousState \in States
    /\ event \in Events \cup {"None"}
    /\ origin \in Origins
    /\ effects \subseteq Effects
    /\ handles \in [HandleIDs -> HandleStates]
    /\ previousHandles \in [HandleIDs -> HandleStates]
    /\ activeHandle \in 0..MaxHandles
    /\ pendingRequests \in [RequestIDs -> {"None", "PendingOpen", "PendingRead", "PendingWrite", "PendingReadDir", "PendingClose", "PendingRequest"}]
    /\ previousPendingRequests \in [RequestIDs -> {"None", "PendingOpen", "PendingRead", "PendingWrite", "PendingReadDir", "PendingClose", "PendingRequest"}]
    /\ activeRequest \in 0..MaxRequests

\* Invariant 1: Initialization Guard
\* No handle operations or allocated handles are permitted before session reaches READY.
NoOperationsBeforeInitialization ==
    state \in {"UNINITIALIZED", "WAIT_VERSION"} =>
        \A h \in HandleIDs : handles[h] = "Unallocated"

ClosedSessionClosesHandles ==
    state = "CLOSED" =>
        \A h \in HandleIDs : handles[h] \in {"Unallocated", "Closed"}

\* Invariant 2: Handle Safety & Type Guards
\* Read/Write requires OpenFile, ReadDir requires OpenDir, CloseHandle requires OpenFile/OpenDir.
HandleTypeOKAndOperationsGuarded ==
    /\ (event \in {"ReadFile", "WriteFile"} => activeHandle # 0 /\ previousHandles[activeHandle] = "OpenFile")
    /\ (event = "ReadDir" => activeHandle # 0 /\ previousHandles[activeHandle] = "OpenDir")
    /\ (event = "CloseHandle" => activeHandle # 0 /\ previousHandles[activeHandle] \in {"OpenFile", "OpenDir"})

\* Invariant 3: Handle Isolation
\* Targeted handle operations alter activeHandle while keeping sibling handles unchanged.
HandleIsolation ==
    activeHandle \in HandleIDs =>
        \A other \in HandleIDs \ {activeHandle} :
            handles[other] = previousHandles[other]

\* Invariant 4: Request ID Correlation & Non-Interference
\* Response fulfillment targets a specific activeRequest and preserves sibling in-flight requests.
RequestCorrelationAndNonInterference ==
    (event \in {"ReceiveData", "ReceiveHandle", "ReceiveName", "ReceiveStatus", "ReceiveAttrs"} /\ activeRequest # 0) =>
        \A other \in RequestIDs \ {activeRequest} :
            pendingRequests[other] = previousPendingRequests[other]

\* ModelView abstraction to reduce state space explosion and keep TLC fast
ModelView == <<
    state,
    handles,
    pendingRequests,
    activeHandle,
    activeRequest,
    NoOperationsBeforeInitialization,
    ClosedSessionClosesHandles,
    HandleTypeOKAndOperationsGuarded,
    HandleIsolation,
    RequestCorrelationAndNonInterference
>>

====

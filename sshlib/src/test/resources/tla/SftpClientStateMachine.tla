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
    /\ requestHandles \in [RequestIDs -> 0..MaxHandles]

\* Invariant 1: Initialization Guard
\* No handle operations or allocated handles are permitted before session reaches READY.
NoOperationsBeforeInitialization ==
    state \in {"UNINITIALIZED", "WAIT_VERSION"} =>
        \A h \in HandleIDs : handles[h] = "Unallocated"

ClosedSessionClosesHandles ==
    state = "CLOSED" =>
        \A h \in HandleIDs : handles[h] \in {"Unallocated", "Closed"}

\* Invariant 2: Handle Safety & Type Guards
\* Read/Write requires a fully confirmed OpenFile, ReadDir requires a confirmed OpenDir.
\* Operations on pending (unconfirmed) handles are forbidden.
HandleTypeOKAndOperationsGuarded ==
    /\ (event \in {"ReadFile", "WriteFile"} => activeHandle # 0 /\ previousHandles[activeHandle] = "OpenFile")
    /\ (event = "ReadDir" => activeHandle # 0 /\ previousHandles[activeHandle] = "OpenDir")
    /\ (event = "CloseHandle" => activeHandle # 0 /\ previousHandles[activeHandle] \in {"PendingFile", "PendingDir", "OpenFile", "OpenDir"})

\* Invariant 3: Handle Isolation
\* Targeted handle operations alter only the intended handle, keeping siblings unchanged.
\* For direct operations (activeHandle # 0), only activeHandle may change.
\* For ReceiveHandle responses, the handle referenced by requestHandles[activeRequest] may change.
HandleIsolation ==
    LET modifiedHandle ==
        IF activeHandle \in HandleIDs THEN activeHandle
        ELSE IF event = "ReceiveHandle" /\ activeRequest \in RequestIDs
             THEN requestHandles[activeRequest]
             ELSE 0
    IN modifiedHandle \in HandleIDs =>
        \A other \in HandleIDs \ {modifiedHandle} :
            handles[other] = previousHandles[other]

\* Invariant 4: Request ID Correlation & Non-Interference
\* Response fulfillment targets a specific activeRequest and preserves sibling in-flight requests.
RequestCorrelationAndNonInterference ==
    (event \in {"ReceiveData", "ReceiveHandle", "ReceiveName", "ReceiveStatus", "ReceiveAttrs"} /\ activeRequest # 0) =>
        \A other \in RequestIDs \ {activeRequest} :
            pendingRequests[other] = previousPendingRequests[other]

\* Invariant 5: Response Semantic Matching
\* Verifies that incoming response events match the expected pending request type.
ResponseSemanticMatching ==
    (event \in {"ReceiveData", "ReceiveHandle", "ReceiveName", "ReceiveStatus", "ReceiveAttrs"} /\ activeRequest # 0) =>
        CASE event = "ReceiveHandle" ->
                previousPendingRequests[activeRequest] = "PendingOpen"
          [] event = "ReceiveData" ->
                previousPendingRequests[activeRequest] = "PendingRead"
          [] event = "ReceiveName" ->
                previousPendingRequests[activeRequest] = "PendingReadDir"
          [] event = "ReceiveAttrs" ->
                previousPendingRequests[activeRequest] = "PendingRequest"
          [] event = "ReceiveStatus" ->
                previousPendingRequests[activeRequest] \in {
                    "PendingOpen",
                    "PendingRead",
                    "PendingWrite",
                    "PendingReadDir",
                    "PendingClose",
                    "PendingRequest"
                }
          [] OTHER -> FALSE

\* Invariant 6: Handle Promotion Safety
\* ReceiveHandle must promote exactly one pending handle; handles must not be usable before promotion.
HandlePromotionSafety ==
    \* When ReceiveHandle fires, exactly one handle must transition from Pending* to Open*
    /\ (event = "ReceiveHandle" /\ activeRequest # 0 =>
        \E h \in HandleIDs :
            /\ previousHandles[h] \in {"PendingFile", "PendingDir"}
            /\ handles[h] = IF previousHandles[h] = "PendingFile" THEN "OpenFile" ELSE "OpenDir"
            /\ \A other \in HandleIDs \ {h} : handles[other] = previousHandles[other])
    \* I/O operations (Read/Write/ReadDir) must never target a pending (unconfirmed) handle
    /\ (event \in {"ReadFile", "WriteFile", "ReadDir"} =>
        \A h \in HandleIDs : handles[h] \notin {"PendingFile", "PendingDir"} \/ handles[h] = previousHandles[h])

\* ModelView abstraction to reduce state space explosion and keep TLC fast
ModelView == <<
    state,
    handles,
    pendingRequests,
    requestHandles,
    activeHandle,
    activeRequest,
    NoOperationsBeforeInitialization,
    ClosedSessionClosesHandles,
    HandleTypeOKAndOperationsGuarded,
    HandleIsolation,
    RequestCorrelationAndNonInterference,
    ResponseSemanticMatching,
    HandlePromotionSafety
>>

====

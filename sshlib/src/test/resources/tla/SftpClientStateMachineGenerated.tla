---- MODULE SftpClientStateMachineGenerated ----
\* Generated from SftpStateMachine. Do not edit.
\* Model SHA-256: 66c6ecb224482047f6437721e0f69ecc6ad240c631519a17776df4038ef3cff1
EXTENDS Naturals

CONSTANT MaxHandles, MaxRequests

HandleIDs == 1..MaxHandles
RequestIDs == 1..MaxRequests

VARIABLES state, previousState, event, origin, effects, previousHandles, activeHandle, handles, previousPendingRequests, activeRequest, pendingRequests

vars == <<state, previousState, event, origin, effects, previousHandles, activeHandle, handles, previousPendingRequests, activeRequest, pendingRequests>>

States == {"CLOSED", "READY", "UNINITIALIZED", "WAIT_VERSION"}
Events == {"CloseHandle", "Disconnect", "OpenDir", "OpenFile", "ReadDir", "ReadFile", "ReceiveAttrs", "ReceiveData", "ReceiveHandle", "ReceiveName", "ReceiveStatus", "ReceiveVersion", "Request", "SendInit", "WriteFile"}
Origins == {"CONNECTION_CONTROL", "LOCAL_COMMAND", "PARSED_PACKET"}
Effects == {"DELIVER_ATTRS", "DELIVER_DATA", "DELIVER_HANDLE", "DELIVER_NAME", "DELIVER_STATUS", "DISCONNECT_SFTP", "RECEIVE_VERSION", "SEND_CLOSE_HANDLE", "SEND_INIT", "SEND_OPEN_DIR", "SEND_OPEN_FILE", "SEND_READ", "SEND_READDIR", "SEND_REQUEST", "SEND_WRITE"}
HandleStates == {"Closed", "OpenDir", "OpenFile", "Unallocated"}

Init ==
    /\ state = "UNINITIALIZED"
    /\ previousState = "UNINITIALIZED"
    /\ event = "None"
    /\ origin = "LOCAL_COMMAND"
    /\ effects = {}
    /\ previousHandles = [h \in HandleIDs |-> "Unallocated"]
    /\ activeHandle = 0
    /\ handles = [h \in HandleIDs |-> "Unallocated"]
    /\ previousPendingRequests = [r \in RequestIDs |-> "None"]
    /\ activeRequest = 0
    /\ pendingRequests = [r \in RequestIDs |-> "None"]

DISCONNECT_READY ==
    /\ state = "READY"
    /\ state' = "CLOSED"
    /\ previousState' = state
    /\ event' = "Disconnect"
    /\ origin' = "CONNECTION_CONTROL"
    /\ effects' = {"DISCONNECT_SFTP"}
    /\ previousHandles' = handles
    /\ activeHandle' = 0
    /\ handles' = [h \in HandleIDs |-> IF handles[h] = "Unallocated" THEN "Unallocated" ELSE "Closed"]
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' = 0
    /\ pendingRequests' = [r \in RequestIDs |-> "None"]

DISCONNECT_UNINITIALIZED ==
    /\ state = "UNINITIALIZED"
    /\ state' = "CLOSED"
    /\ previousState' = state
    /\ event' = "Disconnect"
    /\ origin' = "CONNECTION_CONTROL"
    /\ effects' = {"DISCONNECT_SFTP"}
    /\ previousHandles' = handles
    /\ activeHandle' = 0
    /\ handles' = [h \in HandleIDs |-> IF handles[h] = "Unallocated" THEN "Unallocated" ELSE "Closed"]
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' = 0
    /\ pendingRequests' = [r \in RequestIDs |-> "None"]

DISCONNECT_WAIT_VERSION ==
    /\ state = "WAIT_VERSION"
    /\ state' = "CLOSED"
    /\ previousState' = state
    /\ event' = "Disconnect"
    /\ origin' = "CONNECTION_CONTROL"
    /\ effects' = {"DISCONNECT_SFTP"}
    /\ previousHandles' = handles
    /\ activeHandle' = 0
    /\ handles' = [h \in HandleIDs |-> IF handles[h] = "Unallocated" THEN "Unallocated" ELSE "Closed"]
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' = 0
    /\ pendingRequests' = [r \in RequestIDs |-> "None"]

RECEIVE_VERSION_WAIT_VERSION ==
    /\ state = "WAIT_VERSION"
    /\ state' = "READY"
    /\ previousState' = state
    /\ event' = "ReceiveVersion"
    /\ origin' = "PARSED_PACKET"
    /\ effects' = {"RECEIVE_VERSION"}
    /\ previousHandles' = handles
    /\ activeHandle' = 0
    /\ handles' = handles
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' = 0
    /\ pendingRequests' = pendingRequests

SEND_INIT_UNINITIALIZED ==
    /\ state = "UNINITIALIZED"
    /\ state' = "WAIT_VERSION"
    /\ previousState' = state
    /\ event' = "SendInit"
    /\ origin' = "LOCAL_COMMAND"
    /\ effects' = {"SEND_INIT"}
    /\ previousHandles' = handles
    /\ activeHandle' = 0
    /\ handles' = handles
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' = 0
    /\ pendingRequests' = pendingRequests

AllocateHandle ==
    /\ state = "READY"
    /\ state' = "READY"
    /\ previousState' = state
    /\ event' = "OpenFile"
    /\ origin' = "LOCAL_COMMAND"
    /\ effects' = {"SEND_OPEN_FILE"}
    /\ previousHandles' = handles
    /\ activeHandle' \in HandleIDs
    /\ handles' = [handles EXCEPT ![activeHandle'] = "OpenFile"]
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' \in RequestIDs
    /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "PendingOpen"]
    /\ handles[activeHandle'] = "Unallocated"
    /\ pendingRequests[activeRequest'] = "None"

AllocateDirHandle ==
    /\ state = "READY"
    /\ state' = "READY"
    /\ previousState' = state
    /\ event' = "OpenDir"
    /\ origin' = "LOCAL_COMMAND"
    /\ effects' = {"SEND_OPEN_DIR"}
    /\ previousHandles' = handles
    /\ activeHandle' \in HandleIDs
    /\ handles' = [handles EXCEPT ![activeHandle'] = "OpenDir"]
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' \in RequestIDs
    /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "PendingOpen"]
    /\ handles[activeHandle'] = "Unallocated"
    /\ pendingRequests[activeRequest'] = "None"

ReadFileOp ==
    /\ state = "READY"
    /\ state' = "READY"
    /\ previousState' = state
    /\ event' = "ReadFile"
    /\ origin' = "LOCAL_COMMAND"
    /\ effects' = {"SEND_READ"}
    /\ previousHandles' = handles
    /\ activeHandle' \in HandleIDs
    /\ handles' = handles
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' \in RequestIDs
    /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "PendingRead"]
    /\ handles[activeHandle'] = "OpenFile"
    /\ pendingRequests[activeRequest'] = "None"

WriteFileOp ==
    /\ state = "READY"
    /\ state' = "READY"
    /\ previousState' = state
    /\ event' = "WriteFile"
    /\ origin' = "LOCAL_COMMAND"
    /\ effects' = {"SEND_WRITE"}
    /\ previousHandles' = handles
    /\ activeHandle' \in HandleIDs
    /\ handles' = handles
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' \in RequestIDs
    /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "PendingWrite"]
    /\ handles[activeHandle'] = "OpenFile"
    /\ pendingRequests[activeRequest'] = "None"

ReadDirOp ==
    /\ state = "READY"
    /\ state' = "READY"
    /\ previousState' = state
    /\ event' = "ReadDir"
    /\ origin' = "LOCAL_COMMAND"
    /\ effects' = {"SEND_READDIR"}
    /\ previousHandles' = handles
    /\ activeHandle' \in HandleIDs
    /\ handles' = handles
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' \in RequestIDs
    /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "PendingReadDir"]
    /\ handles[activeHandle'] = "OpenDir"
    /\ pendingRequests[activeRequest'] = "None"

CloseHandleOp ==
    /\ state = "READY"
    /\ state' = "READY"
    /\ previousState' = state
    /\ event' = "CloseHandle"
    /\ origin' = "LOCAL_COMMAND"
    /\ effects' = {"SEND_CLOSE_HANDLE"}
    /\ previousHandles' = handles
    /\ activeHandle' \in HandleIDs
    /\ handles' = [handles EXCEPT ![activeHandle'] = "Closed"]
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' \in RequestIDs
    /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "PendingClose"]
    /\ handles[activeHandle'] \in {"OpenFile", "OpenDir"}
    /\ pendingRequests[activeRequest'] = "None"

RequestOp ==
    /\ state = "READY"
    /\ state' = "READY"
    /\ previousState' = state
    /\ event' = "Request"
    /\ origin' = "LOCAL_COMMAND"
    /\ effects' = {"SEND_REQUEST"}
    /\ previousHandles' = handles
    /\ activeHandle' = 0
    /\ handles' = handles
    /\ previousPendingRequests' = pendingRequests
    /\ activeRequest' \in RequestIDs
    /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "PendingRequest"]
    /\ pendingRequests[activeRequest'] = "None"

FulfillResponse ==
    \/ /\ state = "READY"
       /\ state' = "READY"
       /\ previousState' = state
       /\ event' = "ReceiveHandle"
       /\ origin' = "PARSED_PACKET"
       /\ effects' = {"DELIVER_HANDLE"}
       /\ previousHandles' = handles
       /\ activeHandle' = 0
       /\ handles' = handles
       /\ previousPendingRequests' = pendingRequests
       /\ activeRequest' \in RequestIDs
       /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "None"]
       /\ pendingRequests[activeRequest'] # "None"
    \/ /\ state = "READY"
       /\ state' = "READY"
       /\ previousState' = state
       /\ event' = "ReceiveData"
       /\ origin' = "PARSED_PACKET"
       /\ effects' = {"DELIVER_DATA"}
       /\ previousHandles' = handles
       /\ activeHandle' = 0
       /\ handles' = handles
       /\ previousPendingRequests' = pendingRequests
       /\ activeRequest' \in RequestIDs
       /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "None"]
       /\ pendingRequests[activeRequest'] # "None"
    \/ /\ state = "READY"
       /\ state' = "READY"
       /\ previousState' = state
       /\ event' = "ReceiveName"
       /\ origin' = "PARSED_PACKET"
       /\ effects' = {"DELIVER_NAME"}
       /\ previousHandles' = handles
       /\ activeHandle' = 0
       /\ handles' = handles
       /\ previousPendingRequests' = pendingRequests
       /\ activeRequest' \in RequestIDs
       /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "None"]
       /\ pendingRequests[activeRequest'] # "None"
    \/ /\ state = "READY"
       /\ state' = "READY"
       /\ previousState' = state
       /\ event' = "ReceiveStatus"
       /\ origin' = "PARSED_PACKET"
       /\ effects' = {"DELIVER_STATUS"}
       /\ previousHandles' = handles
       /\ activeHandle' = 0
       /\ handles' = handles
       /\ previousPendingRequests' = pendingRequests
       /\ activeRequest' \in RequestIDs
       /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "None"]
       /\ pendingRequests[activeRequest'] # "None"
    \/ /\ state = "READY"
       /\ state' = "READY"
       /\ previousState' = state
       /\ event' = "ReceiveAttrs"
       /\ origin' = "PARSED_PACKET"
       /\ effects' = {"DELIVER_ATTRS"}
       /\ previousHandles' = handles
       /\ activeHandle' = 0
       /\ handles' = handles
       /\ previousPendingRequests' = pendingRequests
       /\ activeRequest' \in RequestIDs
       /\ pendingRequests' = [pendingRequests EXCEPT ![activeRequest'] = "None"]
       /\ pendingRequests[activeRequest'] # "None"

Next ==
    \/ DISCONNECT_READY
    \/ DISCONNECT_UNINITIALIZED
    \/ DISCONNECT_WAIT_VERSION
    \/ RECEIVE_VERSION_WAIT_VERSION
    \/ SEND_INIT_UNINITIALIZED
    \/ AllocateHandle
    \/ AllocateDirHandle
    \/ ReadFileOp
    \/ WriteFileOp
    \/ ReadDirOp
    \/ CloseHandleOp
    \/ RequestOp
    \/ FulfillResponse

Spec == Init /\ [][Next]_vars
====

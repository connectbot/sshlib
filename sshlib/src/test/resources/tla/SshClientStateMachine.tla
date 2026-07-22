---- MODULE SshClientStateMachine ----
EXTENDS SshClientStateMachineGenerated

AuthenticatedOnlyEffects == {
    "ReceiveChannelFailure",
    "ReceiveChannelOpenConfirmation",
    "ReceiveChannelOpenFailure",
    "ReceiveChannelSuccess",
    "ReceiveGlobalRequest",
    "SendChannelOpen",
    "SendChannelRequest"
}

AuthenticatedOnlyEvents == {
    "AuthorizeAuthenticatedPacket",
    "OpenChannel",
    "ReceiveChannelFailure",
    "ReceiveChannelOpenConfirmation",
    "ReceiveChannelOpenFailure",
    "ReceiveChannelSuccess",
    "ReceiveGlobalRequest",
    "SendChannelRequest"
}

AuthenticationEstablishedStates ==
    {"Authenticated", "Disconnected"} \cup KexStates

HigherLayerOutboundEffects == {
    "SendChannelOpen",
    "SendChannelRequest",
    "SendServiceRequest",
    "SendUserauthRequest"
}

AuthenticationRequestEvents ==
    {"BeginAuthentication"}

TypeOK ==
    /\ state \in States
    /\ previousState \in States
    /\ history \in PostAuthenticatedStates
    /\ event \in Events \cup {"None"}
    /\ origin \in Origins
    /\ packetWasParsed \in BOOLEAN
    /\ effects \subseteq Effects
    /\ rekeying \in BOOLEAN
    /\ authenticationEstablished \in BOOLEAN
    /\ authRequestPending \in BOOLEAN
    /\ previousAuthRequestPending \in BOOLEAN

AuthenticationStateIsMonotonic ==
    authenticationEstablished => state \in AuthenticationEstablishedStates

AuthenticationNeverDowngrades ==
    [] (authenticationEstablished => [] authenticationEstablished)

DisconnectedIsTerminal ==
    [] (state = "Disconnected" => [] (state = "Disconnected"))

NoAuthenticatedEffectsBeforeAuthentication ==
    previousState # "Authenticated" => effects \cap AuthenticatedOnlyEffects = {}

AuthenticatedEventsAreGuarded ==
    event \in AuthenticatedOnlyEvents => previousState = "Authenticated"

ParsedPacketProvenance ==
    origin = "ParsedPacket" => packetWasParsed

NoForgedPacketProvenance ==
    packetWasParsed => origin = "ParsedPacket"

AuthenticationSuccessIsGuarded ==
    event = "AuthenticationSuccess" =>
        /\ previousState = "Authenticating"
        /\ state = "Authenticated"

AuthenticationPacketIsGuarded ==
    event = "AuthorizeAuthenticationPacket" => previousState = "Authenticating"

RekeyStartIsWellFormed ==
    event = "RekeyStarted" =>
        /\ previousState \in PostAuthenticatedStates
        /\ state = "WaitKexInit"
        /\ history = previousState
        /\ rekeying

RekeyingHasSavedPostAuthenticationState ==
    rekeying =>
        /\ state \in KexStates
        /\ history \in PostAuthenticatedStates

RekeyCompletionIsWellFormed ==
    "RekeyComplete" \in effects =>
        /\ event = "ReceiveNewKeys"
        /\ previousState = "WaitNewKeys"
        /\ state = history
        /\ ~rekeying

NoHigherLayerPacketsSentDuringKex ==
    state \in KexStates => effects \cap HigherLayerOutboundEffects = {}

AuthenticationRequestIsGuarded ==
    event \in AuthenticationRequestEvents =>
        /\ previousState \in {"AuthenticationReady", "Authenticating"}
        /\ ~authenticationEstablished
        /\ ~previousAuthRequestPending
        /\ authRequestPending

AuthenticationRequestResponseClearsPending ==
    event \in {"AuthenticationSuccess", "AuthenticationFailure", "AuthorizeAuthenticationPacket"} =>
        ~authRequestPending

====

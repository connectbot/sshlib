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

TypeOK ==
    /\ state \in States
    /\ previousState \in States
    /\ history \in PostAuthenticatedStates
    /\ event \in Events \cup {"None"}
    /\ origin \in Origins
    /\ packetWasParsed \in BOOLEAN
    /\ effects \subseteq Effects
    /\ rekeying \in BOOLEAN

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

====

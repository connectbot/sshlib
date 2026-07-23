---- MODULE SshTerrapin ----
EXTENDS Naturals

\* Focused server-to-client Terrapin abstraction; the opposite direction is symmetric.
\* Protected packets authenticate only when their sequence number matches receiverSeq.
\* InjectUnauthenticatedIgnore includes strict KEX's retrospective "KEXINIT first" check.
\* Cryptographic keys, bytes, and forgery are intentionally outside this control-flow model.

CONSTANT StrictKex

Phases == {"InitialKex", "Encrypted", "Aborted"}
Packets == {"Empty", "ExtInfo", "ServiceAccept"}
SequenceNumbers == 0..2

VARIABLES phase,
          senderSeq,
          receiverSeq,
          wirePacket,
          wireSeq,
          injectedIgnore,
          extInfoSent,
          extInfoReceived,
          extInfoDropped,
          serviceSent,
          serviceAccepted

vars == <<phase,
          senderSeq,
          receiverSeq,
          wirePacket,
          wireSeq,
          injectedIgnore,
          extInfoSent,
          extInfoReceived,
          extInfoDropped,
          serviceSent,
          serviceAccepted>>

Init ==
    /\ phase = "InitialKex"
    /\ senderSeq = 0
    /\ receiverSeq = 0
    /\ wirePacket = "Empty"
    /\ wireSeq = 0
    /\ injectedIgnore = FALSE
    /\ extInfoSent = FALSE
    /\ extInfoReceived = FALSE
    /\ extInfoDropped = FALSE
    /\ serviceSent = FALSE
    /\ serviceAccepted = FALSE

InjectUnauthenticatedIgnore ==
    /\ phase = "InitialKex"
    /\ injectedIgnore = FALSE
    /\ injectedIgnore' = TRUE
    /\ IF StrictKex
          THEN
              /\ phase' = "Aborted"
              /\ receiverSeq' = receiverSeq
          ELSE
              /\ phase' = phase
              /\ receiverSeq' = receiverSeq + 1
    /\ UNCHANGED <<senderSeq,
                    wirePacket,
                    wireSeq,
                    extInfoSent,
                    extInfoReceived,
                    extInfoDropped,
                    serviceSent,
                    serviceAccepted>>

CompleteInitialKex ==
    /\ phase = "InitialKex"
    /\ phase' = "Encrypted"
    /\ IF StrictKex
          THEN
              /\ senderSeq' = 0
              /\ receiverSeq' = 0
          ELSE
              /\ UNCHANGED <<senderSeq, receiverSeq>>
    /\ UNCHANGED <<wirePacket,
                    wireSeq,
                    injectedIgnore,
                    extInfoSent,
                    extInfoReceived,
                    extInfoDropped,
                    serviceSent,
                    serviceAccepted>>

SendExtInfo ==
    /\ phase = "Encrypted"
    /\ wirePacket = "Empty"
    /\ extInfoSent = FALSE
    /\ senderSeq < 2
    /\ wirePacket' = "ExtInfo"
    /\ wireSeq' = senderSeq
    /\ senderSeq' = senderSeq + 1
    /\ extInfoSent' = TRUE
    /\ UNCHANGED <<phase,
                    receiverSeq,
                    injectedIgnore,
                    extInfoReceived,
                    extInfoDropped,
                    serviceSent,
                    serviceAccepted>>

ReceiveExtInfo ==
    /\ phase = "Encrypted"
    /\ wirePacket = "ExtInfo"
    /\ wirePacket' = "Empty"
    /\ IF wireSeq = receiverSeq
          THEN
              /\ receiverSeq' = receiverSeq + 1
              /\ extInfoReceived' = TRUE
              /\ phase' = phase
          ELSE
              /\ receiverSeq' = receiverSeq
              /\ extInfoReceived' = extInfoReceived
              /\ phase' = "Aborted"
    /\ UNCHANGED <<senderSeq,
                    wireSeq,
                    injectedIgnore,
                    extInfoSent,
                    extInfoDropped,
                    serviceSent,
                    serviceAccepted>>

DropExtInfo ==
    /\ phase = "Encrypted"
    /\ wirePacket = "ExtInfo"
    /\ wirePacket' = "Empty"
    /\ extInfoDropped' = TRUE
    /\ UNCHANGED <<phase,
                    senderSeq,
                    receiverSeq,
                    wireSeq,
                    injectedIgnore,
                    extInfoSent,
                    extInfoReceived,
                    serviceSent,
                    serviceAccepted>>

SendServiceAccept ==
    /\ phase = "Encrypted"
    /\ wirePacket = "Empty"
    /\ extInfoSent
    /\ serviceSent = FALSE
    /\ senderSeq < 2
    /\ wirePacket' = "ServiceAccept"
    /\ wireSeq' = senderSeq
    /\ senderSeq' = senderSeq + 1
    /\ serviceSent' = TRUE
    /\ UNCHANGED <<phase,
                    receiverSeq,
                    injectedIgnore,
                    extInfoSent,
                    extInfoReceived,
                    extInfoDropped,
                    serviceAccepted>>

ReceiveServiceAccept ==
    /\ phase = "Encrypted"
    /\ wirePacket = "ServiceAccept"
    /\ wirePacket' = "Empty"
    /\ IF wireSeq = receiverSeq
          THEN
              /\ receiverSeq' = receiverSeq + 1
              /\ serviceAccepted' = TRUE
              /\ phase' = phase
          ELSE
              /\ receiverSeq' = receiverSeq
              /\ serviceAccepted' = serviceAccepted
              /\ phase' = "Aborted"
    /\ UNCHANGED <<senderSeq,
                    wireSeq,
                    injectedIgnore,
                    extInfoSent,
                    extInfoReceived,
                    extInfoDropped,
                    serviceSent>>

Next ==
    \/ InjectUnauthenticatedIgnore
    \/ CompleteInitialKex
    \/ SendExtInfo
    \/ ReceiveExtInfo
    \/ DropExtInfo
    \/ SendServiceAccept
    \/ ReceiveServiceAccept

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ StrictKex \in BOOLEAN
    /\ phase \in Phases
    /\ senderSeq \in SequenceNumbers
    /\ receiverSeq \in SequenceNumbers
    /\ wirePacket \in Packets
    /\ wireSeq \in SequenceNumbers
    /\ injectedIgnore \in BOOLEAN
    /\ extInfoSent \in BOOLEAN
    /\ extInfoReceived \in BOOLEAN
    /\ extInfoDropped \in BOOLEAN
    /\ serviceSent \in BOOLEAN
    /\ serviceAccepted \in BOOLEAN

TerrapinSucceeded ==
    /\ extInfoDropped
    /\ extInfoReceived = FALSE
    /\ serviceAccepted
    /\ phase # "Aborted"

NoTerrapin == ~TerrapinSucceeded

StrictInjectionAborts ==
    StrictKex /\ injectedIgnore => phase = "Aborted"

====

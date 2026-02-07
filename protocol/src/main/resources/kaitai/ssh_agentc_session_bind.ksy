meta:
  id: ssh_agentc_session_bind
  title: session-bind@openssh.com Extension
  endian: be
  imports:
  - byte_string
doc: |
  OpenSSH session binding extension payload.
  Binds the agent to a specific SSH session to prevent signature request hijacking.
seq:
  - id: hostkey
    type: byte_string
    doc: Server host key from key exchange
  - id: session_identifier
    type: byte_string
    doc: SSH session identifier (H from key exchange)
  - id: signature
    type: byte_string
    doc: Signature of (hostkey || session_identifier) by host key
  - id: is_forwarding
    type: u1
    doc: 1 if this is for agent forwarding, 0 otherwise

meta:
  id: ssh_agent_message
  title: SSH Agent Protocol Message
  endian: be
  imports:
  - ssh_agentc_request_identities
  - ssh_agentc_sign_request
  - ssh_agentc_extension
doc: |
  Top-level SSH agent protocol message framing (IETF draft-miller-ssh-agent).
  Used for SSH agent forwarding where remote servers make agent requests.
seq:
  - id: length
    type: u4
    doc: Length of message_type + payload
  - id: message_type
    type: u1
    doc: Agent message type code
  - id: payload
    size: length - 1
    type:
      switch-on: message_type
      cases:
        11: ssh_agentc_request_identities
        13: ssh_agentc_sign_request
        27: ssh_agentc_extension

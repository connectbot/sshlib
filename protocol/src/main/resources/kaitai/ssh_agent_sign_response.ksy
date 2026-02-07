meta:
  id: ssh_agent_sign_response
  title: SSH_AGENT_SIGN_RESPONSE
  endian: be
  imports:
  - byte_string
doc: |
  Response to SIGN_REQUEST (type 14).
  Contains the signature blob.
seq:
  - id: signature
    type: byte_string
    doc: SSH-encoded signature blob

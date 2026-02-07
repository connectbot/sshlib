meta:
  id: ssh_agentc_sign_request
  title: SSH_AGENTC_SIGN_REQUEST
  endian: be
  imports:
  - byte_string
doc: |
  Sign request message (type 13).
  Server requests the agent to sign data with a specific key.
seq:
  - id: key_blob
    type: byte_string
    doc: Public key blob to sign with
  - id: data
    type: byte_string
    doc: Data to be signed
  - id: flags
    type: u4
    doc: Signature flags (0 for default, 2 for RSA_SHA2_256, 4 for RSA_SHA2_512)

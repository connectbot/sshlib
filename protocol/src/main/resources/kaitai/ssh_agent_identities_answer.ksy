meta:
  id: ssh_agent_identities_answer
  title: SSH_AGENT_IDENTITIES_ANSWER
  endian: be
  imports:
  - byte_string
doc: |
  Response to REQUEST_IDENTITIES (type 12).
  Returns list of available public keys.
seq:
  - id: nkeys
    type: u4
    doc: Number of keys in the response
  - id: identities
    type: identity
    repeat: expr
    repeat-expr: nkeys
    doc: List of available identities
types:
  identity:
    seq:
      - id: key_blob
        type: byte_string
        doc: Public key blob
      - id: comment
        type: byte_string
        doc: Key comment (human-readable description)

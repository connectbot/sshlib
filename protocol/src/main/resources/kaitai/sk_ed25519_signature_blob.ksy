meta:
  id: sk_ed25519_signature_blob
  endian: be
  imports:
    - byte_string
doc: >
  OpenSSH Security Key Ed25519 signature blob.
  Defined in OpenSSH PROTOCOL.u2f section 3.2.
seq:
  - id: signature
    type: byte_string
    doc: Raw Ed25519 signature (64 bytes)
  - id: flags
    type: u1
    doc: FIDO2 device flags (e.g. 0x01 for UP)
  - id: counter
    type: u4
    doc: FIDO2 device signature counter

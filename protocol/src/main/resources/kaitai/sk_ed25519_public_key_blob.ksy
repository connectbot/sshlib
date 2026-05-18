meta:
  id: sk_ed25519_public_key_blob
  endian: be
  imports:
    - byte_string
doc: >
  OpenSSH Security Key Ed25519 public key blob.
  Defined in OpenSSH PROTOCOL.u2f section 3.1.
seq:
  - id: public_key
    type: byte_string
    doc: Ed25519 public key (32 bytes)
  - id: application
    type: byte_string
    doc: Relying-party identifier (e.g. "ssh:")

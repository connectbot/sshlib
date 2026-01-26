meta:
  id: ssh_ed25519_public_key_blob
  endian: be
  imports:
  - byte_string
doc-ref: RFC 8709 section 4
seq:
- id: key
  type: byte_string
  doc: Ed25519 public key (32 bytes)

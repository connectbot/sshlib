meta:
  id: ssh_ed25519_signature_blob
  endian: be
  imports:
  - byte_string
doc-ref: RFC 8709 section 6
seq:
- id: signature
  type: byte_string
  doc: Ed25519 signature (64 bytes)

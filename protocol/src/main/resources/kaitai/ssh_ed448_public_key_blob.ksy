meta:
  id: ssh_ed448_public_key_blob
  endian: be
  imports:
  - byte_string
doc-ref: RFC 8709 section 4
seq:
- id: key
  type: byte_string
  doc: Ed448 public key (57 bytes)

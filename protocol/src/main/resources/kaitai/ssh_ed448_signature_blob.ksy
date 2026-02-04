meta:
  id: ssh_ed448_signature_blob
  endian: be
  imports:
  - byte_string
doc-ref: RFC 8709 section 6
seq:
- id: signature
  type: byte_string
  doc: Ed448 signature (114 bytes)

meta:
  id: ssh_rsa_signature_blob
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4253 section 6.6
seq:
- id: signature
  type: byte_string
  doc: RSA signature (integer s in network byte order)

meta:
  id: ssh_dss_signature_blob
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4253 section 6.6
seq:
- id: signature
  type: byte_string
  doc: DSS signature (160-bit r followed by 160-bit s, 40 bytes total)

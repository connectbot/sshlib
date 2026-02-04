meta:
  id: ssh_dss_public_key_blob
  endian: be
  imports:
  - mpint
doc-ref: RFC 4253 section 6.6
seq:
- id: p
  type: mpint
  doc: DSS prime p
- id: q
  type: mpint
  doc: DSS subprime q
- id: g
  type: mpint
  doc: DSS generator g
- id: y
  type: mpint
  doc: DSS public key y

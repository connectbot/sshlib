meta:
  id: ssh_msg_kex_dh_gex_group
  endian: be
  imports:
  - mpint
doc-ref: RFC 4419 section 3
seq:
- id: p
  type: mpint
  doc: safe prime
- id: g
  type: mpint
  doc: generator for subgroup GF(p)

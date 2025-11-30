meta:
  id: ssh_msg_kex_dh_gex_init
  endian: be
  imports:
  - mpint
doc-ref: RFC 4419 section 3
seq:
- id: e
  type: mpint
  doc: e = g^x mod p

meta:
  id: ssh_msg_kex_ecdh_init
  endian: be
  imports:
  - byte_string
doc-ref: RFC 5656 section 4
doc: Elliptic Curve Diffie-Hellman key exchange initialization packet
seq:
- id: q_c
  doc: Client's ephemeral public key octet string
  type: byte_string

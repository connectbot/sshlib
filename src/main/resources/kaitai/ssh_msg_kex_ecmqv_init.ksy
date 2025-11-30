meta:
  id: ssh_msg_kex_ecmqv_init
  endian: be
  imports:
  - byte_string
doc-ref: RFC 5656 section 5
doc: Elliptic Curve Menezes-Qu-Vanstone key exchange initialization packet
seq:
- id: q_c
  doc: Client's ephemeral public key octet string
  type: byte_string

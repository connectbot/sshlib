meta:
  id: ssh_msg_kexdh_init
  endian: be
  imports:
  - mpint
doc-ref: RFC 4253 section 8
doc: Diffie-Hellman key exchange initialization packet
seq:
- id: e
  doc: >
    Client's public key portion of ephemeral Diffie-Hellman key exchange
    (i.e., e = g^x mod p).
  type: mpint

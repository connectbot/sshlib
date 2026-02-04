meta:
  id: kex_dh_gex_hash
  endian: be
  imports:
  - byte_string
  - mpint
doc: This is the exchange hash input used to authenticate the key.
doc-ref: RFC 4419 section 3
seq:
- id: v_c
  doc: the client's identification string
  type: byte_string
- id: v_s
  doc: the server's identification string
  type: byte_string
- id: i_c
  doc: the payload of the client's SSH_MSG_KEXINIT
  type: byte_string
- id: i_s
  doc: the payload of the server's SSH_MSG_KEXINIT
  type: byte_string
- id: k_s
  doc: the host key
  type: byte_string
- id: min
  type: u4
  doc: minimal size in bits of an acceptable broup
- id: n
  type: u4
  doc: preferred size in bits of the group the server will send
- id: max
  type: u4
  doc: maximal size in bits of an acceptable group
- id: p
  type: mpint
  doc: safe prime
- id: g
  type: mpint
  doc: generator for subgroup GF(p)
- id: e
  doc: exchange value sent by the client
  type: mpint
- id: f
  doc: exchange value sent by the server
  type: mpint
- id: k
  doc: the shared secret
  type: mpint

meta:
  id: ssh_msg_kex_dh_gex_reply
  endian: be
  imports:
  - byte_string
  - mpint
doc-ref: RFC 4419 section 3
seq:
- id: server_public_host_key
  type: byte_string
  doc: server public host key and certificates (K_S)
- id: f
  type: mpint
- id: signature_h
  type: byte_string
  doc: signature of H

meta:
  id: ssh_msg_kexrsa_pubkey
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4432 section 4
seq:
- id: server_public
  type: byte_string
  doc: server public host key and certificate (K_S)
- id: transient_key
  type: byte_string
  doc: K_T, transient RSA public key

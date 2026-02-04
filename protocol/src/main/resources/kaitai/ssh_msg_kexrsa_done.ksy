meta:
  id: ssh_msg_kexrsa_done
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4432 section 4
seq:
- id: signature_h
  type: byte_string
  doc: signature of H with the host key

meta:
  id: global_request_hostkeys_prove_00_openssh
  endian: be
  imports:
  - byte_string
doc-ref: openssh-PROTOCOL.txt
seq:
- id: signature
  type: byte_string
  doc: Signature proving possession of private host keys

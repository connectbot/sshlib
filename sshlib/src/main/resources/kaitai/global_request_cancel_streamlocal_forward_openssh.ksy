meta:
  id: global_request_cancel_streamlocal_forward_openssh
  endian: be
  imports:
  - byte_string
doc-ref: openssh-PROTOCOL.txt
seq:
- id: socket_path
  type: byte_string
  doc: Unix domain socket path

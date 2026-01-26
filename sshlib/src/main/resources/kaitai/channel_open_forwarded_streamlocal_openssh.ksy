meta:
  id: channel_open_forwarded_streamlocal_openssh
  endian: be
  imports:
  - byte_string
doc-ref: openssh-PROTOCOL.txt
seq:
- id: socket_path
  type: byte_string
  doc: Unix domain socket path that was connected
- id: reserved
  type: byte_string
  doc: Reserved for future use

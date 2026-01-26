meta:
  id: channel_open_direct_streamlocal_openssh
  endian: be
  imports:
  - byte_string
doc-ref: openssh-PROTOCOL.txt
seq:
- id: socket_path
  type: byte_string
  doc: Unix domain socket path to connect to
- id: reserved_1
  type: byte_string
  doc: Reserved for future use
- id: reserved_2
  type: u4
  doc: Reserved for future use

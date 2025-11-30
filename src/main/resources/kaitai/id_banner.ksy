meta:
  id: id_banner
  endian: be
  imports: []
seq:
- id: prefix
  contents: SSH-
- id: proto_version
  type: str
  encoding: UTF-8
  terminator: 10

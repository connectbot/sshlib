meta:
  id: ssh_msg_kex_dh_gex_request
  endian: be
  imports: []
doc-ref: RFC 4419 section 3
seq:
- id: min
  type: u4
  doc: minimal size in bits of an acceptable broup
- id: n
  type: u4
  doc: preferred size in bits of the group the server will send
- id: max
  type: u4
  doc: maximal size in bits of an acceptable group

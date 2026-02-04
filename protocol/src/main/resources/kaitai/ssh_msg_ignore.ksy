meta:
  id: ssh_msg_ignore
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4253 section 11.2
doc: >
  This is a message that must be ignored. It can be used to defeat traffic
  analysis.
seq:
- id: data
  type: byte_string

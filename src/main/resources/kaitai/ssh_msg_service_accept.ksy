meta:
  id: ssh_msg_service_accept
  endian: be
  imports:
  - ascii_string
doc-ref: RFC 4253 section 10
seq:
- id: service_name
  type: ascii_string

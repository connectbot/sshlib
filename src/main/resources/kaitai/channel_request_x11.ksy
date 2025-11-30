meta:
  id: channel_request_x11
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4254 section 6.3.2
seq:
- id: originator_address
  type: byte_string
  doc: Originator address (e.g., "192.168.7.38")
- id: originator_port
  type: u4

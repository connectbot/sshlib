meta:
  id: global_request_cancel_tcpip_forward
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4254 section 7.1
seq:
- id: address_to_bind
  type: byte_string
  doc: Address to bind (e.g., "0.0.0.0")
- id: port_to_bind
  type: u4
  doc: Port number to bind

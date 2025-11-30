meta:
  id: channel_open_forwarded_tcpip
  endian: be
  imports:
  - byte_string
doc: >
  Implementations MUST reject these messages unless they previously
  requested a remove TCP/IP port forwarding with the given port number.
doc-ref: RFC 4254 section 7.2
seq:
- id: connected_address
  doc: Address that was connected
  type: byte_string
- id: connected_port
  doc: Port that was connected
  type: u4
- id: originator_address
  doc: Originator IP address
  type: byte_string
- id: originator_port
  doc: Originator port
  type: u4

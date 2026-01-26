meta:
  id: channel_open_direct_tcpip
  endian: be
  imports:
  - byte_string
doc: >
  When a connection comes to a locally forwarded TCP/IP port, the
  following packet is sent to the other side. Note that these messages
  MAY also be sent for ports for which no forwarding has been explicitly
  requested. The receiving side must decide whether to allow the
  forwarding.
doc-ref: RFC 4254 section 7.2
seq:
- id: host_to_connect
  doc: Host to connect
  type: byte_string
- id: port_to_connect
  doc: Port to connect
  type: u4
- id: originator_address
  doc: Originator IP address
  type: byte_string
- id: originator_port
  doc: Originator port
  type: u4

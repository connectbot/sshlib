meta:
  id: ssh_msg_unimplemented
  endian: be
  imports: []
doc-ref: RFC 4253 section 11.4
doc: This is sent in reply to an unknown packet type.
seq:
- id: packet_sequence
  doc: Indicates the packet sequence number that was unrecognized.
  type: u4

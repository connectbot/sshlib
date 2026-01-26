meta:
  id: ssh_msg_channel_window_adjust
  endian: be
  imports: []
doc-ref: RFC 4254 section 5.2
seq:
- id: recipient_channel
  type: u4
- id: bytes_to_add
  type: u4

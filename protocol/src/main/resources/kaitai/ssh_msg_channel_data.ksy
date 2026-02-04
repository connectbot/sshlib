meta:
  id: ssh_msg_channel_data
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4254 section 5.2
seq:
- id: recipient_channel
  type: u4
- id: data
  type: byte_string

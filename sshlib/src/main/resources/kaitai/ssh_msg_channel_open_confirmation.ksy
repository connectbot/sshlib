meta:
  id: ssh_msg_channel_open_confirmation
  endian: be
  imports: []
doc: >
  The recipient channel is the channel number given in the original
  open request, the sender channel is the channel number allocated
  by the other side.
seq:
- id: recipient_channel
  type: u4
- id: sender_channel
  type: u4
- id: initial_window_size
  type: u4
- id: maximum_packet_size
  type: u4

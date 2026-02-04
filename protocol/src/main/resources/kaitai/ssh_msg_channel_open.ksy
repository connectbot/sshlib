meta:
  id: ssh_msg_channel_open
  endian: be
  imports:
  - ascii_string
  - channel_open_direct_streamlocal_openssh
  - channel_open_direct_tcpip
  - channel_open_forwarded_streamlocal_openssh
  - channel_open_forwarded_tcpip
  - channel_open_session
  - channel_open_tun_openssh
  - channel_open_x11
  - invalid_message
doc-ref: RFC 4254 section 5.1
seq:
- id: channel_type
  type: ascii_string
- id: sender_channel
  type: u4
- id: initial_window_size
  type: u4
- id: maximum_packet_size
  type: u4
- id: channel_specific_data
  type:
    switch-on: channel_type.value
    cases:
      '"session"': channel_open_session
      '"x11"': channel_open_x11
      '"forwarded-tcpip"': channel_open_forwarded_tcpip
      '"direct-tcpip"': channel_open_direct_tcpip
      '"tun@openssh.com"': channel_open_tun_openssh
      '"direct-streamlocal@openssh.com"': channel_open_direct_streamlocal_openssh
      '"forwarded-streamlocal@openssh.com"': channel_open_forwarded_streamlocal_openssh
      _: invalid_message

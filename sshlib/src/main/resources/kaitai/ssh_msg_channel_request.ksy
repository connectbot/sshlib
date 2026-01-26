meta:
  id: ssh_msg_channel_request
  endian: be
  imports:
  - ascii_string
  - channel_request_env
  - channel_request_exec
  - channel_request_exit_signal
  - channel_request_exit_status
  - channel_request_pty_req
  - channel_request_shell
  - channel_request_signal
  - channel_request_subsystem
  - channel_request_window_change
  - channel_request_x11
  - channel_request_x11_req
  - channel_request_xon_xoff
  - invalid_message
doc-ref: RFC 4254 section 5.4
seq:
- id: recipient_channel
  type: u4
- id: request_type
  type: ascii_string
- id: want_reply
  type: u1
- id: request_specific_fields
  type:
    switch-on: request_type.value
    cases:
      '"pty-req"': channel_request_pty_req
      '"x11-req"': channel_request_x11_req
      '"x11"': channel_request_x11
      '"env"': channel_request_env
      '"shell"': channel_request_shell
      '"exec"': channel_request_exec
      '"subsystem"': channel_request_subsystem
      '"window-change"': channel_request_window_change
      '"xon-xoff"': channel_request_xon_xoff
      '"signal"': channel_request_signal
      '"exit-status"': channel_request_exit_status
      '"exit-signal"': channel_request_exit_signal
      _: invalid_message

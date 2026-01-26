meta:
  id: ssh_msg_global_request
  endian: be
  imports:
  - ascii_string
  - global_request_cancel_streamlocal_forward_openssh
  - global_request_cancel_tcpip_forward
  - global_request_hostkeys_00_openssh
  - global_request_hostkeys_prove_00_openssh
  - global_request_streamlocal_forward_openssh
  - global_request_tcpip_forward
  - invalid_message
doc-ref: RFC 4254 section 4
seq:
- id: request_name
  type: ascii_string
- id: want_reply
  type: u1
- id: request_specific_fields
  type:
    switch-on: request_name.value
    cases:
      '"tcpip-forward"': global_request_tcpip_forward
      '"cancel-tcpip-forward"': global_request_cancel_tcpip_forward
      '"streamlocal-forward@openssh.com"': global_request_streamlocal_forward_openssh
      '"cancel-streamlocal-forward@openssh.com"': global_request_cancel_streamlocal_forward_openssh
      '"hostkeys-00@openssh.com"': global_request_hostkeys_00_openssh
      '"hostkeys-prove-00@openssh.com"': global_request_hostkeys_prove_00_openssh
      _: invalid_message

meta:
  id: kex_dh_gex_payload
  endian: be
  imports:
  - invalid_message
  - ssh_enums
  - ssh_msg_kex_dh_gex_group
  - ssh_msg_kex_dh_gex_init
  - ssh_msg_kex_dh_gex_reply
  - ssh_msg_kex_dh_gex_request
  - ssh_msg_kex_dh_gex_request_old
seq:
- id: message_type
  type: u1
  enum: ssh_enums::kex_dh_gex
- id: body
  size-eos: true
  type:
    switch-on: message_type
    cases:
      ssh_enums::kex_dh_gex::ssh_msg_kex_dh_gex_request_old: ssh_msg_kex_dh_gex_request_old
      ssh_enums::kex_dh_gex::ssh_msg_kex_dh_gex_request: ssh_msg_kex_dh_gex_request
      ssh_enums::kex_dh_gex::ssh_msg_kex_dh_gex_group: ssh_msg_kex_dh_gex_group
      ssh_enums::kex_dh_gex::ssh_msg_kex_dh_gex_init: ssh_msg_kex_dh_gex_init
      ssh_enums::kex_dh_gex::ssh_msg_kex_dh_gex_reply: ssh_msg_kex_dh_gex_reply
      _: invalid_message

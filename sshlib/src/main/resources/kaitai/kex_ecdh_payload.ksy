meta:
  id: kex_ecdh_payload
  endian: be
  imports:
  - invalid_message
  - ssh_enums
  - ssh_msg_kex_ecdh_init
  - ssh_msg_kex_ecdh_reply
seq:
- id: message_type
  type: u1
  enum: ssh_enums::kex_ecdh
- id: body
  size-eos: true
  type:
    switch-on: message_type
    cases:
      ssh_enums::kex_ecdh::ssh_msg_kex_ecdh_init: ssh_msg_kex_ecdh_init
      ssh_enums::kex_ecdh::ssh_msg_kex_ecdh_reply: ssh_msg_kex_ecdh_reply
      _: invalid_message

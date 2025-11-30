meta:
  id: kex_ecmqv_payload
  endian: be
  imports:
  - invalid_message
  - ssh_enums
  - ssh_msg_kex_ecmqv_init
  - ssh_msg_kex_ecmqv_reply
seq:
- id: message_type
  type: u1
  enum: ssh_enums::kex_ecmqv
- id: body
  size-eos: true
  type:
    switch-on: message_type
    cases:
      ssh_enums::kex_ecmqv::ssh_msg_kex_ecmqv_init: ssh_msg_kex_ecmqv_init
      ssh_enums::kex_ecmqv::ssh_msg_kex_ecmqv_reply: ssh_msg_kex_ecmqv_reply
      _: invalid_message

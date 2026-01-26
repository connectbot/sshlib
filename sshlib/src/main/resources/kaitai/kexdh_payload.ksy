meta:
  id: kexdh_payload
  endian: be
  imports:
  - invalid_message
  - ssh_enums
  - ssh_msg_kexdh_init
  - ssh_msg_kexdh_reply
seq:
- id: message_type
  type: u1
  enum: ssh_enums::kex_dh
- id: body
  size-eos: true
  type:
    switch-on: message_type
    cases:
      ssh_enums::kex_dh::ssh_msg_kexdh_init: ssh_msg_kexdh_init
      ssh_enums::kex_dh::ssh_msg_kexdh_reply: ssh_msg_kexdh_reply
      _: invalid_message

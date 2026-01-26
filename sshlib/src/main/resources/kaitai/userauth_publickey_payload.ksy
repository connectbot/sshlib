meta:
  id: userauth_publickey_payload
  endian: be
  imports:
  - invalid_message
  - ssh_enums
  - ssh_msg_userauth_pk_ok
seq:
- id: message_type
  type: u1
  enum: ssh_enums::message_userauth_publickey
- id: body
  size-eos: true
  type:
    switch-on: message_type
    cases:
      ssh_enums::message_userauth_publickey::ssh_msg_userauth_pk_ok: ssh_msg_userauth_pk_ok
      _: invalid_message

meta:
  id: userauth_password_payload
  endian: be
  imports:
  - invalid_message
  - ssh_enums
  - ssh_msg_userauth_passwd_changereq
seq:
- id: message_type
  type: u1
  enum: ssh_enums::message_userauth_password
- id: body
  size-eos: true
  type:
    switch-on: message_type
    cases:
      ssh_enums::message_userauth_password::ssh_msg_userauth_passwd_changereq: ssh_msg_userauth_passwd_changereq
      _: invalid_message

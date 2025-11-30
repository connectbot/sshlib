meta:
  id: userauth_keyboard_interactive_payload
  endian: be
  imports:
  - invalid_message
  - ssh_enums
  - ssh_msg_userauth_info_request
  - ssh_msg_userauth_info_response
seq:
- id: message_type
  type: u1
  enum: ssh_enums::message_userauth_keyboard_interactive
- id: body
  size-eos: true
  type:
    switch-on: message_type
    cases:
      ssh_enums::message_userauth_keyboard_interactive::ssh_msg_userauth_info_request: ssh_msg_userauth_info_request
      ssh_enums::message_userauth_keyboard_interactive::ssh_msg_userauth_info_response: ssh_msg_userauth_info_response
      _: invalid_message

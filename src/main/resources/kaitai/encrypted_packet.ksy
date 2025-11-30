meta:
  id: encrypted_packet
  endian: be
  imports:
  - invalid_message
  - ssh_enums
  - ssh_msg_channel_close
  - ssh_msg_channel_data
  - ssh_msg_channel_eof
  - ssh_msg_channel_extended_data
  - ssh_msg_channel_failure
  - ssh_msg_channel_open
  - ssh_msg_channel_open_confirmation
  - ssh_msg_channel_open_failure
  - ssh_msg_channel_request
  - ssh_msg_channel_success
  - ssh_msg_channel_window_adjust
  - ssh_msg_global_request
  - ssh_msg_request_failure
  - ssh_msg_request_success
  - ssh_msg_userauth_banner
  - ssh_msg_userauth_failure
  - ssh_msg_userauth_request
  - ssh_msg_userauth_success
params:
- id: len_mac
  type: u4
  doc: The length of the MAC used for encrypted packets.
seq:
- id: len_encrypted_payload
  type: u4
- id: encrypted_payload
  size: len_encrypted_payload
- id: mac
  size: len_mac
types:
  decrypted_packet:
    seq:
    - id: len_random_padding
      type: u1
    - id: payload
      type: decrypted_payload
      size: _parent.as<encrypted_packet>.len_encrypted_payload - len_random_padding -
        1
    - id: random_padding
      size: len_random_padding
  decrypted_payload:
    seq:
    - id: message_type
      type: u1
      enum: ssh_enums::message_type
    - id: body
      size: _parent.as<decrypted_packet>._parent.as<encrypted_packet>.len_encrypted_payload
        - _parent.as<decrypted_packet>.len_random_padding - 2
      type:
        switch-on: message_type
        cases:
          ssh_enums::message_type::ssh_msg_userauth_request: ssh_msg_userauth_request
          ssh_enums::message_type::ssh_msg_userauth_failure: ssh_msg_userauth_failure
          ssh_enums::message_type::ssh_msg_userauth_success: ssh_msg_userauth_success
          ssh_enums::message_type::ssh_msg_userauth_banner: ssh_msg_userauth_banner
          ssh_enums::message_type::ssh_msg_global_request: ssh_msg_global_request
          ssh_enums::message_type::ssh_msg_request_success: ssh_msg_request_success
          ssh_enums::message_type::ssh_msg_request_failure: ssh_msg_request_failure
          ssh_enums::message_type::ssh_msg_channel_open: ssh_msg_channel_open
          ssh_enums::message_type::ssh_msg_channel_open_confirmation: ssh_msg_channel_open_confirmation
          ssh_enums::message_type::ssh_msg_channel_open_failure: ssh_msg_channel_open_failure
          ssh_enums::message_type::ssh_msg_channel_window_adjust: ssh_msg_channel_window_adjust
          ssh_enums::message_type::ssh_msg_channel_data: ssh_msg_channel_data
          ssh_enums::message_type::ssh_msg_channel_extended_data: ssh_msg_channel_extended_data
          ssh_enums::message_type::ssh_msg_channel_eof: ssh_msg_channel_eof
          ssh_enums::message_type::ssh_msg_channel_close: ssh_msg_channel_close
          ssh_enums::message_type::ssh_msg_channel_request: ssh_msg_channel_request
          ssh_enums::message_type::ssh_msg_channel_success: ssh_msg_channel_success
          ssh_enums::message_type::ssh_msg_channel_failure: ssh_msg_channel_failure
          _: invalid_message

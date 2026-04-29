meta:
  id: ssh_msg_userauth_request
  endian: be
  imports:
  - ascii_string
  - invalid_message
  - userauth_request_external_keyx
  - userauth_request_gssapi
  - userauth_request_gssapi_keyex
  - userauth_request_gssapi_with_mic
  - userauth_request_hostbased
  - userauth_request_keyboard_interactive
  - userauth_request_none
  - userauth_request_password
  - userauth_request_publickey
  - userauth_request_publickey_hostbound
doc-ref: RFC 4252 section 5
seq:
- id: user_name
  type: ascii_string
- id: service_name
  type: ascii_string
- id: method_name
  type: ascii_string
- id: method_specific_fields
  type:
    switch-on: method_name.value
    cases:
      '"publickey"': userauth_request_publickey
      '"publickey-hostbound-v00@openssh.com"': userauth_request_publickey_hostbound
      '"password"': userauth_request_password
      '"hostbased"': userauth_request_hostbased
      '"none"': userauth_request_none
      '"keyboard-interactive"': userauth_request_keyboard_interactive
      '"gssapi-with-mic"': userauth_request_gssapi_with_mic
      '"gssapi-keyex"': userauth_request_gssapi_keyex
      '"gssapi"': userauth_request_gssapi
      '"external-keyx"': userauth_request_external_keyx
      _: invalid_message

meta:
  id: ssh_msg_userauth_failure
  endian: be
  imports:
  - name_list
doc-ref: RFC 4252 section 5.1
seq:
- id: valid_authentications
  type: name_list
  doc: Authentication methods that can continue
- id: partial_success
  type: u1

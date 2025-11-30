meta:
  id: ssh_msg_channel_open_failure
  endian: be
  imports:
  - byte_string
doc: >
  If the recipent of the SSH_MSG_CHANNEL_OPEN message does not
  support the specified ''channel type,'' it simply responds with
  SSH_MSG_CHANNEL_OPEN_FAILURE. The client MAY show the ''description''
  string to the user. If this is done, the client software should take
  the precautions discussed in SSH-ARCH.
doc-ref: RFC 4254 section 5.1
seq:
- id: recipient_channel
  type: u4
- id: reason_code
  type: u4
- id: description
  type: byte_string
- id: language_tag
  type: byte_string

meta:
  id: channel_request_exit_signal
  endian: be
  imports:
  - byte_string
  - utf8_string
doc-ref: RFC 4254 section 6.10
seq:
- id: signal_name
  type: byte_string
  doc: Signal name (without the "SIG" prefix)
- id: core_dumped
  type: u1
- id: error_message
  type: utf8_string
  doc: error message in UTF-8 encoding
- id: language_tag
  type: byte_string
  doc: language tag in RFC 3066 format

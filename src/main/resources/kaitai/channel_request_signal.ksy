meta:
  id: channel_request_signal
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4254 section 6.9
seq:
- id: signal_name
  type: byte_string
  doc: Signal name (without the "SIG" prefix)

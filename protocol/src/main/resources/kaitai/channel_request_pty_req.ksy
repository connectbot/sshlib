meta:
  id: channel_request_pty_req
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4254 section 6.2
seq:
- id: term
  type: byte_string
  doc: TERM environment variable value (e.g., vt100)
- id: terminal_width
  type: u4
  doc: terminal width, characters (e.g., 80)
- id: terminal_height
  type: u4
  doc: terminal height, rows (e.g., 24)
- id: terminal_width_pixels
  type: u4
  doc: terminal width, pixels (e.g., 640)
- id: terminal_height_pixels
  type: u4
  doc: terminal height, pixels (e.g., 480)
- id: terminal_modes
  type: byte_string
  doc: encoded terminal modes

meta:
  id: channel_request_window_change
  endian: be
  imports: []
doc-ref: RFC 4254 section 6.7
seq:
- id: terminal_width
  type: u4
  doc: terminal width, columns (e.g., "80")
- id: terminal_height
  type: u4
  doc: terminal height, rows (e.g., "24")
- id: terminal_width_pixels
  type: u4
  doc: terminal width, pixels (e.g., "640")
- id: terminal_height_pixels
  type: u4
  doc: terminal height, pixels (e.g., "480")

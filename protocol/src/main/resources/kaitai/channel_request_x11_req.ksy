meta:
  id: channel_request_x11_req
  endian: be
  imports:
  - byte_string
doc-ref: RFC 4254 section 6.3.1
seq:
- id: single_connection
  type: u1
- id: x11_auth_protocol
  type: byte_string
  doc: X11 authentication protocol (e.g., "MIT-MAGIC-COOKIE-1")
- id: x11_auth_cookie
  type: byte_string
  doc: X11 authentication cookie; hex-encoded
- id: x11_screen_number
  type: u4
  doc: X11 screen number

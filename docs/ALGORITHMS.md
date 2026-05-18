# Supported SSH Algorithms

This document lists the cryptographic algorithms supported by the ConnectBot SSH library.

## Authentication
- `keyboard-interactive`
- `password`
- `publickey` (including FIDO2 / Security Key algorithms `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`)

## Host Keys
- `ssh-ed25519` ([RFC 8709](https://tools.ietf.org/html/rfc8709))
- `ssh-ed448` ([RFC 8709](https://tools.ietf.org/html/rfc8709))
- `ecdsa-sha2-nistp256` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-3))
- `ecdsa-sha2-nistp384` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-3))
- `ecdsa-sha2-nistp521` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-3))
- `rsa-sha2-512` ([RFC 8332](https://tools.ietf.org/html/rfc8332#section-3))
- `rsa-sha2-256` ([RFC 8332](https://tools.ietf.org/html/rfc8332#section-3))
- `ssh-rsa` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1))

## Key Exchange
- `mlkem768x25519-sha256` ([draft-ietf-sshm-mlkem-hybrid-kex](https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/)) (depends on JEP-496 support)
- `curve25519-sha256` ([RFC 8731](https://tools.ietf.org/html/rfc8731))
- `ecdh-sha2-nistp521` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
- `ecdh-sha2-nistp384` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
- `ecdh-sha2-nistp256` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
- `diffie-hellman-group18-sha512` ([RFC 8268](https://tools.ietf.org/html/rfc8268))
- `diffie-hellman-group16-sha512` ([RFC 8268](https://tools.ietf.org/html/rfc8268))
- `diffie-hellman-group14-sha256` ([RFC 8268](https://tools.ietf.org/html/rfc8268))
- `diffie-hellman-group-exchange-sha256` ([RFC 4419](https://tools.ietf.org/html/rfc4419))
- `diffie-hellman-group14-sha1` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1))
- `diffie-hellman-group-exchange-sha1` ([RFC 4419](https://tools.ietf.org/html/rfc4419))
- `diffie-hellman-group1-sha1` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1))

## Encryption
- `chacha20-poly1305@openssh.com` ([draft-ietf-sshm-chacha20-poly1305](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-chacha20-poly1305))
- `aes256-gcm@openssh.com` ([draft-miller-sshm-aes-gcm](https://datatracker.ietf.org/doc/html/draft-miller-sshm-aes-gcm))
- `aes128-gcm@openssh.com` ([draft-miller-sshm-aes-gcm](https://datatracker.ietf.org/doc/html/draft-miller-sshm-aes-gcm))
- `aes256-ctr` ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
- `aes128-ctr` ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
- `aes256-cbc` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3))
- `aes128-cbc` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3))
- `3des-cbc` ([RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253#section-6.3))

## MACs
- `hmac-sha2-512-etm@openssh.com` ([OpenSSH PROTOCOL](https://github.com/openssh/openssh-portable/blob/60b909fb110f77c1ffd15cceb5d09b8e3f79b27e/PROTOCOL#L50))
- `hmac-sha2-256-etm@openssh.com` ([OpenSSH PROTOCOL](https://github.com/openssh/openssh-portable/blob/60b909fb110f77c1ffd15cceb5d09b8e3f79b27e/PROTOCOL#L50))
- `hmac-sha1-etm@openssh.com` ([OpenSSH PROTOCOL](https://github.com/openssh/openssh-portable/blob/60b909fb110f77c1ffd15cceb5d09b8e3f79b27e/PROTOCOL#L50))
- `hmac-sha2-512` ([RFC 4868](https://tools.ietf.org/html/rfc4868))
- `hmac-sha2-256` ([RFC 4868](https://tools.ietf.org/html/rfc4868))
- `hmac-sha1` ([RFC 4253](https://tools.ietf.org/html/rfc4253))

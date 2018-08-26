# ConnectBot's SSH library
[![Build Status](https://travis-ci.org/connectbot/sshlib.svg?branch=master)](https://travis-ci.org/connectbot/sshlib)
[![Download](https://api.bintray.com/packages/connectbot/maven/sshlib/images/download.svg)](https://bintray.com/connectbot/maven/sshlib/_latestVersion)

This is ConnectBot's SSH library. It started as a continuation of the Trilead SSH2 library,
but has had several features added to it since then.

This library retains its original [3-Clause BSD license](
https://opensource.org/licenses/BSD-3-Clause).

##### Encryption:
  * aes256-ctr ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
  * aes128-ctr ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
  * aes256-cbc ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3))
  * aes128-cbc ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3))

##### MACs:
  * hmac-sha2-512-etm@openssh.com ([OpenSSH PROTOCOL](
    https://github.com/openssh/openssh-portable/blob/e1b26ce504662a5d5b991091228984ccfd25f280/PROTOCOL#L54))
  * hmac-sha2-256-etm@openssh.com ([OpenSSH PROTOCOL](
    https://github.com/openssh/openssh-portable/blob/e1b26ce504662a5d5b991091228984ccfd25f280/PROTOCOL#L54))
  * hmac-sha1-etm@openssh.com ([OpenSSH PROTOCOL](
    https://github.com/openssh/openssh-portable/blob/e1b26ce504662a5d5b991091228984ccfd25f280/PROTOCOL#L54))
  * hmac-sha2-512 ([RFC 4868](https://tools.ietf.org/html/rfc4868))
  * hmac-sha2-256 ([RFC 4868](https://tools.ietf.org/html/rfc4868))
  * hmac-sha1 ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.4))
  
##### Key support:
  * Ed25519 ([draft-ietf-curdle-ssh-ed25519-ed448-03](
    https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-ed448-03))
  * ECDSA ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-3))
  * RSA  ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.6))

##### Key exchange:
  * ecdh-sha2-nistp521 ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
  * ecdh-sha2-nistp384 ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
  * ecdh-sha2-nistp256 ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
  * curve25519-sha256 ([curve25519-sha256](https://tools.ietf.org/id/draft-ietf-curdle-ssh-curves-07.html))
  * diffie-hellman-group-exchange-sha256 ([RFC 4419](https://tools.ietf.org/html/rfc4419))
  * diffie-hellman-group-exchange-sha1 ([RFC 4419](https://tools.ietf.org/html/rfc4419))
  * diffie-hellman-group1-sha1 ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1))
  * diffie-hellman-group14-sha1 ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1))

# ConnectBot's SSH library
[![Build Status](https://travis-ci.org/connectbot/sshlib.svg?branch=master)](https://travis-ci.org/connectbot/sshlib)
[![Download](https://api.bintray.com/packages/connectbot/maven/sshlib/images/download.svg)](https://bintray.com/connectbot/maven/sshlib/_latestVersion)

This is ConnectBot's SSH library. It started as a continuation of the Trilead SSH2 library,
but has had several features added to it since then.

This library retains its original [3-Clause BSD license](
https://opensource.org/licenses/BSD-3-Clause).

##### Key support:
  * ECDSA (RFC 5656)
  * Ed25519 (draft-bjh21-ssh-ed25519-02)

##### Key exchange:
  * ECDH (RFC 5656)
  * X25519 (curve25519-sha256@libssh.org)

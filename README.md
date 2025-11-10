# pam-ussh

[![Go Report Card](https://goreportcard.com/badge/github.com/andrewheberle/pam-ussh?logo=go&style=flat-square)](https://goreportcard.com/report/github.com/andrewheberle/pam-ussh)
[![codecov](https://codecov.io/gh/andrewheberle/pam-ussh/graph/badge.svg?token=CDLzj2pg5W)](https://codecov.io/gh/andrewheberle/pam-ussh)

This is a fork of Uber's SSH certificate pam module.

This is a PAM module that will authenticate a user based on them having an SSH certificate in
their ssh-agent signed by a specified SSH CA. 

This is primarily intended as an authentication module for sudo. Using it for something else 
may be unsafe and is totally untested.

An example usage would be you SSH to a remote machine and sshd authenticates you (probably 
using your SSH certificate, because if you're using it for this, you're probably using it for sshd 
as well). At that point when you want to run a command that requires authentication (eg. 
`sudo`), you can use pam-ussh for authentication.

Works on Linux and OSX. BSD doesn't work because Go doesn't (yet) support `buildmode=c-shared`
on BSD.

## Building

1. Clone the repo and run 'make'
```sh
  git clone https://github.com/andrewheberle/pam-ussh.git
  cd pam-ussh
  make
```

## Usage

1. Put this PAM module where ever PAM modules live on your system, eg.
`/lib/security`

2. Add it as an authentication method to `/etc/pam.d/sudo` (this example is
from Ubuntu 24.04 LTS), eg.

```
  $ cat /etc/pam.d/sudo
  #%PAM-1.0

  # Set up user limits from /etc/security/limits.conf.
  session    required   pam_limits.so

  session    required   pam_env.so readenv=1 user_readenv=0
  session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0

  # attempt SSH certificate based auth for sudo access
  auth [success=done default=ignore] /lib/security/pam_ussh.so

  @include common-auth
  @include common-account
  @include common-session-noninteractive
```

3. Make sure your `SSH_AUTH_SOCK` is available where you want to use this (eg. ssh -A user@host)

Runtime configuration options:
* `ca_file` - string, the path to your TrustedUserCAKeys file, default `/etc/ssh/ca.pub`.
  This is the pubkey that signs your user certificates.

* `authorized_principals` - string, comma separated list of authorized principals, default `""`.
  If set, the user needs to have a principal in this list in order to use this module. If
  this and `authorized_principals_file` are both set, only the last option listed is checked.

* `authorized_principals_file` - string, path to an authorized_principals file, default `""`.
  If set, users need to have a principal listed in this file in order to use this module.
  If this and `authorized_principals` are both set, only the last option listed is checked.

* `no_require_user_principal` - flag, true if present
  If set, certificates do not have to be valid for a principal matching the local user in addition
  to one of the principals listed in `authorized_principals` or `authorized_principals_file`.

## Example configuration

1. The following looks for a certificate on `$SSH_AUTH_SOCK` that has been signed by `/etc/ssh/ca.pub`.
The certificate must be valid for at least one principal that's listed in `/etc/ssh/sudo_principals`.
   ```
   auth [success=done default=ignore] /lib/security/pam_ussh.so ca_file=/etc/ssh/ca.pub authorized_principals_file=/etc/ssh/sudo_principals no_require_user_principal
   ```

2. The following looks for a certificate on `$SSH_AUTH_SOCK` that has been signed by `/etc/ssh/ca.pub`.
The certificate must be valid for at least one principal that's listed in `/etc/ssh/sudo_principals`.
The certificate must also be valid for a principal matching the username of the target user.

   ```
   auth [success=done default=ignore] /lib/security/pam_ussh.so ca_file=/etc/ssh/ca.pub authorized_principals_file=/etc/ssh/sudo_principals
   ```

## FAQ

* Are you associated with Uber?
  - No, I have no association with Uber

* How do I report a security issue?
  - Please report security issues privately via GitHub

* does this work with non-certificate ssh-keys?
  - I have no plans to support non-certificate based ssh-keys


Information on ssh certificates:
* http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=HEAD
* https://blog.habets.se/2011/07/OpenSSH-certificates.html

# pam-ussh

[![codecov](https://codecov.io/gh/andrewheberle/pam-ussh/graph/badge.svg?token=CDLzj2pg5W)](https://codecov.io/gh/andrewheberle/pam-ussh)

This is a fork of Uber's SSH certificate PAM module.

This is a PAM module that will authenticate a user based on them having an SSH certificate in
their ssh-agent signed by a specified SSH CA.

This is primarily intended as an authentication module for sudo. Using it for something else
may be unsafe and is totally untested.

An example usage would be you SSH to a remote machine and sshd authenticates you (probably
using your SSH certificate, because if you're using it for this, you're probably using it for sshd
as well). At that point when you want to run a command that requires authentication (eg.
`sudo`), you can use pam-ussh for authentication.

Built and packaged for Linux (amd64 and arm64). The build tags also allow macOS, but it is
untested there.

## Building

Building needs Go, a C compiler and the PAM development headers (eg. `gcc` and `libpam0g-dev`
on Debian/Ubuntu), with cgo enabled:

```sh
git clone https://github.com/andrewheberle/pam-ussh.git
cd pam-ussh
CGO_ENABLED=1 go build -buildmode=c-shared -o pam_ussh.so
sudo install -D -m 0644 pam_ussh.so /usr/lib/security/pam_ussh.so
```

`go build` also writes a C header, `pam_ussh.h`, which isn't needed and can be deleted.

## Installing via Package

```sh
curl -fsSL https://packages.hebs.net.au/pam-ussh/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/pam-ussh.gpg
echo "deb [signed-by=/usr/share/keyrings/pam-ussh.gpg] https://packages.hebs.net.au/pam-ussh stable main" | sudo tee /etc/apt/sources.list.d/pam-ussh.list
sudo apt-get update
sudo apt-get install pam-ussh
```

Packages are published for amd64 and arm64. The package installs the module to
`/usr/lib/security/pam_ussh.so`; it doesn't change any PAM configuration (see Usage).

## Usage

1. Install the module, either from the package or by building it (see above). Both put it at
`/usr/lib/security/pam_ussh.so`. That directory isn't on PAM's default module path on Debian and
Ubuntu (which use `/usr/lib/<arch>-linux-gnu/security`), so refer to the module by its full path
in PAM configuration.

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
  auth [success=done default=ignore] /usr/lib/security/pam_ussh.so

  @include common-auth
  @include common-account
  @include common-session-noninteractive
```

3. Make sure your `SSH_AUTH_SOCK` is available where you want to use this (eg. ssh -A user@host)

Only user certificates that list at least one principal are accepted. As with `sshd`, a
certificate signed without principals (eg. `ssh-keygen -s ca` without `-n`) and host
certificates (`ssh-keygen -h`) are rejected.

Runtime configuration options:
* `ca_file` - string, the path to your TrustedUserCAKeys file, default `/etc/ssh/ca.pub`.
  This is the pubkey that signs your user certificates.

* `authorized_principals` - string, comma separated list of authorized principals, default `""`.
  If set, the user needs to have a principal in this list in order to use this module. If
  this and `authorized_principals_file` are both set, only the last option listed is checked.
  Likewise, if it is given more than once, only the last list is used.

* `authorized_principals_file` - string, path to an authorized_principals file, default `""`.
  If set, users need to have a principal listed in this file in order to use this module.
  If this and `authorized_principals` are both set, only the last option listed is checked.

* `no_require_user_principal` - flag, true if present
  If set, certificates do not have to be valid for a principal matching the user running `sudo` in
  addition to one of the principals listed in `authorized_principals` or `authorized_principals_file`.
  It must be combined with one of those options; on its own, every authentication fails.

* `agent_timeout` - duration, how long to wait for the ssh-agent, default `30s`.
  A Go duration such as `10s` or `1m30s`; `0` waits indefinitely. This covers the whole exchange
  with the agent, including waiting for a touch on a hardware key. If the agent doesn't respond in
  time, authentication fails.

`ca_file`, `authorized_principals`, `authorized_principals_file` and `agent_timeout` require a value (eg. `ca_file=/etc/ssh/ca.pub`).
If any of them is given without one, authentication fails. Unknown options are logged and ignored.

## Logging

The module logs to syslog with the `auth` facility and the tag `pam-ussh`. Each line's syslog
priority matches its level:

| `level` | syslog priority | used for |
| --- | --- | --- |
| `INFO` | `info` | successful authentication, `ca_file` in use |
| `WARN` | `warning` | failed authentication, configuration problems |
| `ERROR` | `err` | failing to drop or restore privileges, closing files or connections, disabling ptrace |

Each line is a set of `key=value` pairs, for example:

```
level=INFO msg="authentication succeeded" user=alice uid=1000 principal=alice key_id=alice@example serial=42
level=WARN msg="authentication failed" user=alice uid=1000 err="no valid certificates: ..."
```

## Example configuration

Each example is a line for `/etc/pam.d/sudo`, placed before `@include common-auth` as shown in Usage.

1. The following looks for a certificate on `$SSH_AUTH_SOCK` that has been signed by `/etc/ssh/ca.pub`.
The certificate must be valid for at least one principal that's listed in `/etc/ssh/sudo_principals`.
   ```
   auth [success=done default=ignore] /usr/lib/security/pam_ussh.so ca_file=/etc/ssh/ca.pub authorized_principals_file=/etc/ssh/sudo_principals no_require_user_principal
   ```

2. The following looks for a certificate on `$SSH_AUTH_SOCK` that has been signed by `/etc/ssh/ca.pub`.
The certificate must be valid for at least one principal that's listed in `/etc/ssh/sudo_principals`.
The certificate must also be valid for a principal matching the username of the user running `sudo`.

   ```
   auth [success=done default=ignore] /usr/lib/security/pam_ussh.so ca_file=/etc/ssh/ca.pub authorized_principals_file=/etc/ssh/sudo_principals
   ```

## FAQ

* Are you associated with Uber?
  - No, I have no association with Uber

* How do I report a security issue?
  - Please report security issues privately via GitHub

* Does this work with non-certificate ssh-keys?
  - I have no plans to support non-certificate based SSH-keys


Information on SSH certificates:
* http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=HEAD
* https://blog.habets.se/2011/07/OpenSSH-certificates.html

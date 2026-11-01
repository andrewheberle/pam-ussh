# pam-ussh

Authenticating a user, typically for sudo, by the SSH certificates held in their ssh-agent.

## Language

**User CA**:
The set of CA public keys, loaded from `ca_file`, whose signatures on a user certificate are trusted.
_Avoid_: CA file, trusted keys

**Required principal**:
A principal the certificate must be valid for; by default the name of the user being authenticated, and disabled by `no_require_user_principal`.
_Avoid_: user principal, username principal

**Authorized principals**:
The set of principals, from `authorized_principals` or `authorized_principals_file`, at least one of which the certificate must carry.
_Avoid_: allowed principals, sudo principals, group

**Possession proof**:
The agent signing a random challenge with a certificate's private key, showing it holds the key and not just the certificate.
_Avoid_: challenge, signature check

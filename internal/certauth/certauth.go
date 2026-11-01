/*
Copyright (c) 2017 Uber Technologies, Inc.
Copyright (c) 2025 Andrew Heberle

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// Package certauth verifies that an ssh-agent holds a certificate, signed by
// the User CA, that satisfies a Policy.
package certauth

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	// ErrEmptyPolicy means the Policy has neither a required principal nor
	// any authorized principals.
	ErrEmptyPolicy = errors.New("no required principal and no authorized principals")
	// ErrNoValidCA means the User CA contains no valid public keys.
	ErrNoValidCA = errors.New("no valid keys in User CA")
	// ErrNoCertificates means the agent holds no certificates.
	ErrNoCertificates = errors.New("no certificates loaded")
	// ErrNotUserCertificate means a certificate is not a user certificate
	// (eg. it is a host certificate).
	ErrNotUserCertificate = errors.New("not a user certificate")
	// ErrNoPrincipals means a certificate has no principals. Such a
	// certificate would otherwise be valid for every principal.
	ErrNoPrincipals = errors.New("certificate has no principals")
	// ErrPrincipalMismatch means a certificate is not valid for the required
	// principal or any of the authorized principals.
	ErrPrincipalMismatch = errors.New("certificate not valid for policy principals")
	// ErrUnknownAuthority means a certificate is not signed by the User CA.
	ErrUnknownAuthority = errors.New("certificate signed by unrecognized authority")
	// ErrProofFailed means the agent could not prove possession of the
	// private key for a certificate.
	ErrProofFailed = errors.New("possession proof failed")
)

// Policy is what a certificate must satisfy.
type Policy struct {
	// RequiredPrincipal, if set, must be a principal the certificate is
	// valid for. Typically the local username.
	RequiredPrincipal string
	// AuthorizedPrincipals, if set, must overlap with the certificate's
	// principals.
	AuthorizedPrincipals []string
}

// Match describes the certificate that satisfied the Policy.
type Match struct {
	KeyID     string
	Serial    uint64
	Principal string
}

// Verify checks the certificates held by a against policy, accepting only
// those signed by one of the User CA keys in caKeys (authorized_keys format).
// It returns the first certificate that satisfies the policy and whose
// private key the agent proves it holds.
//
// On failure the error wraps one of the package's sentinel errors, joined
// with the reason each certificate was rejected.
func Verify(policy Policy, caKeys []byte, a agent.Agent) (Match, error) {
	if len(policy.RequiredPrincipal) == 0 && len(policy.AuthorizedPrincipals) == 0 {
		return Match{}, ErrEmptyPolicy
	}

	caPubkeys := parseCAKeys(caKeys)
	if len(caPubkeys) == 0 {
		return Match{}, ErrNoValidCA
	}

	keys, err := a.List()
	if err != nil {
		return Match{}, fmt.Errorf("listing keys: %w", err)
	}
	if len(keys) == 0 {
		return Match{}, ErrNoCertificates
	}

	c := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			for _, k := range caPubkeys {
				if bytes.Equal(auth.Marshal(), k.Marshal()) {
					return true
				}
			}
			return false
		},
	}

	authorized := make(map[string]struct{}, len(policy.AuthorizedPrincipals))
	for _, p := range policy.AuthorizedPrincipals {
		authorized[p] = struct{}{}
	}

	var rejections []error
	for _, key := range keys {
		pubKey, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			continue
		}

		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			continue
		}

		if cert.CertType != ssh.UserCert {
			rejections = append(rejections, fmt.Errorf("certificate %q: %w", cert.KeyId, ErrNotUserCertificate))
			continue
		}

		// CheckCert treats a cert with no principals as valid for every
		// principal; like sshd, refuse it
		if len(cert.ValidPrincipals) == 0 {
			rejections = append(rejections, fmt.Errorf("certificate %q: %w", cert.KeyId, ErrNoPrincipals))
			continue
		}

		principal, err := matchPrincipal(c, policy.RequiredPrincipal, authorized, cert)
		if err != nil {
			rejections = append(rejections, fmt.Errorf("certificate %q: %w", cert.KeyId, err))
			continue
		}

		if !c.IsUserAuthority(cert.SignatureKey) {
			rejections = append(rejections, fmt.Errorf("certificate %q: %w", cert.KeyId, ErrUnknownAuthority))
			continue
		}

		// for the ssh agent to sign some data validating that they do in fact
		// have the private key
		randBytes := make([]byte, 32)
		if _, err := rand.Read(randBytes); err != nil {
			return Match{}, fmt.Errorf("reading random bytes: %w", err)
		}

		// a failed proof only rules out this cert; another may still succeed
		signedData, err := a.Sign(pubKey, randBytes)
		if err != nil {
			rejections = append(rejections, fmt.Errorf("certificate %q: %w: signing: %w", cert.KeyId, ErrProofFailed, err))
			continue
		}

		if err := pubKey.Verify(randBytes, signedData); err != nil {
			rejections = append(rejections, fmt.Errorf("certificate %q: %w: verifying signature: %w", cert.KeyId, ErrProofFailed, err))
			continue
		}

		return Match{KeyID: cert.KeyId, Serial: cert.Serial, Principal: principal}, nil
	}

	if len(rejections) == 0 {
		return Match{}, ErrNoCertificates
	}
	return Match{}, fmt.Errorf("no valid certificates: %w", errors.Join(rejections...))
}

// matchPrincipal checks cert against the required principal (if set) and the
// authorized principals (if any), returning the principal it matched: the
// first of the cert's principals that is authorized, otherwise the required
// principal.
//
// CheckCert also enforces the validity window, critical options and the CA
// signature, so it runs at least once for every cert that is accepted.
func matchPrincipal(c *ssh.CertChecker, required string, authorized map[string]struct{}, cert *ssh.Certificate) (string, error) {
	// Optionally, we may require that the cert be valid for a
	// required principal, typically the local username
	if len(required) > 0 {
		if err := c.CheckCert(required, cert); err != nil {
			return "", fmt.Errorf("required principal %q: %w: %w", required, ErrPrincipalMismatch, err)
		}
		if len(authorized) == 0 {
			return required, nil
		}
	}

	// The cert must carry at least one authorized principal
	for _, p := range cert.ValidPrincipals {
		if _, ok := authorized[p]; !ok {
			continue
		}
		if len(required) == 0 {
			if err := c.CheckCert(p, cert); err != nil {
				return "", fmt.Errorf("authorized principal %q: %w: %w", p, ErrPrincipalMismatch, err)
			}
		}
		return p, nil
	}

	return "", ErrPrincipalMismatch
}

// parseCAKeys returns the public keys in b, skipping any that fail to parse.
func parseCAKeys(b []byte) []ssh.PublicKey {
	var keys []ssh.PublicKey
	in := b
	for {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(in)
		if err == nil {
			keys = append(keys, pubKey)
		}
		if len(rest) == 0 {
			break
		}
		in = rest
	}
	return keys
}

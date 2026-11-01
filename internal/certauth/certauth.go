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

		certValidFor := ""
		// Optionally, we may require that the cert be valid for a
		// required principal, typically the local username
		if len(policy.RequiredPrincipal) > 0 {
			if err := c.CheckCert(policy.RequiredPrincipal, cert); err != nil {
				rejections = append(rejections, fmt.Errorf("certificate %q: required principal %q: %w: %w", cert.KeyId, policy.RequiredPrincipal, ErrPrincipalMismatch, err))
				continue
			}
			certValidFor = policy.RequiredPrincipal
		}

		// If authorized principals are set, the cert must be valid for at least one of them
		if len(authorized) > 0 {
			for _, p := range policy.AuthorizedPrincipals {
				if err := c.CheckCert(p, cert); err != nil {
					continue
				}
				certValidFor = p
				break
			}
			if len(certValidFor) == 0 {
				rejections = append(rejections, fmt.Errorf("certificate %q: %w", cert.KeyId, ErrPrincipalMismatch))
				continue
			}
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

		signedData, err := a.Sign(pubKey, randBytes)
		if err != nil {
			return Match{}, fmt.Errorf("certificate %q: %w: signing: %w", cert.KeyId, ErrProofFailed, err)
		}

		if err := pubKey.Verify(randBytes, signedData); err != nil {
			return Match{}, fmt.Errorf("certificate %q: %w: verifying signature: %w", cert.KeyId, ErrProofFailed, err)
		}

		if len(authorized) == 0 {
			return Match{KeyID: cert.KeyId, Serial: cert.Serial, Principal: certValidFor}, nil
		}

		for _, p := range cert.ValidPrincipals {
			if _, ok := authorized[p]; ok {
				return Match{KeyID: cert.KeyId, Serial: cert.Serial, Principal: p}, nil
			}
		}
		rejections = append(rejections, fmt.Errorf("certificate %q: %w", cert.KeyId, ErrPrincipalMismatch))
	}

	if len(rejections) == 0 {
		return Match{}, ErrNoCertificates
	}
	return Match{}, fmt.Errorf("no valid certificates: %w", errors.Join(rejections...))
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

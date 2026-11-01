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

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/andrewheberle/pam-ussh/internal/certauth"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestLoadPrincipals(t *testing.T) {
	WithTempDir(func(dir string) {
		p := path.Join(dir, "principals")
		if err := os.WriteFile(p, []byte("group:t"), 0444); err != nil {
			panic(err)
		}

		r, err := loadValidPrincipals(p)
		if err != nil {
			t.Fatal("loadValidPrincipals(): failed unexpectedly")
		}
		if _, ok := r["group:t"]; !ok {
			t.Error("loadValidPrincipals(): did not get expected principal")
		}
	})
}

func TestNoAuthSock(t *testing.T) {
	oldAgent := os.Getenv("SSH_AUTH_SOCK")
	defer func() {
		if err := os.Setenv("SSH_AUTH_SOCK", oldAgent); err != nil {
			panic(err)
		}
	}()
	if err := os.Unsetenv("SSH_AUTH_SOCK"); err != nil {
		panic(err)
	}
	got := authenticate(0, certauth.Policy{RequiredPrincipal: "r"}, "")
	if got != AuthError {
		t.Errorf("authenticate(): got %v want %v", got, AuthError)
	}
}

func TestBadAuthSock(t *testing.T) {
	WithTempDir(func(dir string) {
		s := path.Join(dir, "badsock")

		oldAgent := os.Getenv("SSH_AUTH_SOCK")
		defer func() {
			if err := os.Setenv("SSH_AUTH_SOCK", oldAgent); err != nil {
				panic(err)
			}
		}()
		if err := os.Setenv("SSH_AUTH_SOCK", s); err != nil {
			panic(err)
		}
		got := authenticate(0, certauth.Policy{RequiredPrincipal: "r"}, "")
		if got != AuthError {
			t.Errorf("authenticate(): got %v want %v", got, AuthError)
		}
	})
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name       string
		username   string
		args       []string
		wantErr    bool
		wantPolicy certauth.Policy
		wantUserCA string
	}{
		{"defaults", "testuser", []string{}, false, certauth.Policy{RequiredPrincipal: "testuser"}, defaultUserCA},
		{"defaults with unknown option", "testuser", []string{"some_unknown_setting"}, false, certauth.Policy{RequiredPrincipal: "testuser"}, defaultUserCA},
		{"alternate ca", "testuser", []string{"ca_file=/etc/ssh_ca.pub"}, false, certauth.Policy{RequiredPrincipal: "testuser"}, "/etc/ssh_ca.pub"},
		{"alternate group", "testuser", []string{"group=testgroup"}, false, certauth.Policy{RequiredPrincipal: "testuser"}, defaultUserCA},
		{"no requre user", "testuser", []string{"no_require_user_principal"}, false, certauth.Policy{}, defaultUserCA},
		{"list of authorized_principals", "testuser", []string{"authorized_principals=admin3,admin1,admin2"}, false, certauth.Policy{RequiredPrincipal: "testuser", AuthorizedPrincipals: []string{"admin1", "admin2", "admin3"}}, defaultUserCA},
		{"missing authorized_principals_file", "testuser", []string{"authorized_principals_file=missing"}, true, certauth.Policy{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, userCA, err := parseArgs(tt.username, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("succeeded unexpectedly")
				}
				return
			}
			if err != nil {
				t.Fatalf("failed unexpectedly: %v", err)
			}

			if !reflect.DeepEqual(tt.wantPolicy, policy) {
				t.Errorf("policy got %+v want %+v", policy, tt.wantPolicy)
			}

			if tt.wantUserCA != userCA {
				t.Errorf("userCA got %v want %v", userCA, tt.wantUserCA)
			}
		})
	}
}

// TestPamAuthorize covers the plumbing around certauth.Verify; the
// certificate rules themselves are tested in internal/certauth.
func TestPamAuthorize(t *testing.T) {
	WithTempDir(func(dir string) {
		ca := path.Join(dir, "ca")
		caPamOpt := fmt.Sprintf("ca_file=%s", ca)

		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		signer, err := ssh.NewSignerFromKey(k)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(ca, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0444); err != nil {
			panic(err)
		}

		userPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		userPub, err := ssh.NewPublicKey(&userPriv.PublicKey)
		if err != nil {
			panic(err)
		}
		c := signedCert(userPub, signer, "foober", []string{"group:foober"})

		WithSSHAgent(func(a agent.Agent) {
			if err := a.Add(agent.AddedKey{PrivateKey: userPriv, Certificate: c}); err != nil {
				panic(err)
			}

			uid := getUID()

			tests := []struct {
				name     string
				username string
				argv     []string
				want     AuthResult
			}{
				{"missing ca file fails", "foober", []string{"ca_file=missing"}, AuthError},
				{"valid certificate succeeds", "foober", []string{caPamOpt}, AuthSuccess},
				{"bad authorized_principals_file fails", "foober", []string{caPamOpt, "authorized_principals_file=foober"}, AuthError},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					if got := pamAuthenticate(uid, tt.username, tt.argv); got != tt.want {
						t.Errorf("pamAuthenticate(): got %v want %v", got, tt.want)
					}
				})
			}
		})
	})
}

func signedCert(pubKey ssh.PublicKey, signer ssh.Signer, u string, p []string) *ssh.Certificate {
	c := &ssh.Certificate{
		ValidPrincipals: []string{u},
		Key:             pubKey,
		Serial:          1,
		CertType:        ssh.UserCert,
		ValidAfter:      uint64(time.Now().Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(1 * time.Minute).Unix()),
	}

	if p != nil {
		c.ValidPrincipals = append(c.ValidPrincipals, p...)
	}

	if e := c.SignCert(rand.Reader, signer); e != nil {
		panic(e)
	}
	return c
}

// WithTempDir runs the func `fn` with the given temporary directory.
// 'Borrowed' from cerberus.
func WithTempDir(fn func(dir string)) {
	dir, err := os.MkdirTemp("", "ussh-test")
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			panic(err)
		}
	}()
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := os.Chdir(cwd); err != nil {
			panic(err)
		}
	}()
	if err := os.Chdir(dir); err != nil {
		panic(err)
	}

	fn(dir)
}

func WithSSHAgent(fn func(agent.Agent)) {
	a := agent.NewKeyring()
	WithTempDir(func(dir string) {
		newAgent := path.Join(dir, "agent")
		oldAgent := os.Getenv("SSH_AUTH_SOCK")
		if err := os.Setenv("SSH_AUTH_SOCK", newAgent); err != nil {
			panic(err)
		}
		defer func() {
			if err := os.Setenv("SSH_AUTH_SOCK", oldAgent); err != nil {
				panic(err)
			}
		}()

		l, e := net.Listen("unix", newAgent)
		if e != nil {
			panic(e)
		}

		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					panic(e)
				}
				go func() {
					defer func() {
						if err := c.Close(); err != nil {
							panic(err)
						}
					}()
					_ = agent.ServeAgent(a, c)
				}()
			}
		}()

		fn(a)
	})
}

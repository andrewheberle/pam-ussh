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
	got := authenticate(0, "r", "", nil)
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
		got := authenticate(0, "r", "", nil)
		if got != AuthError {
			t.Errorf("authenticate(): got %v want %v", got, AuthError)
		}
	})
}

func TestBadCA(t *testing.T) {
	WithTempDir(func(dir string) {
		ca := path.Join(dir, "badca")
		WithSSHAgent(func(a agent.Agent) {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			if err := a.Add(agent.AddedKey{PrivateKey: k}); err != nil {
				panic(err)
			}
			got := authenticate(0, "", ca, nil)
			if got != AuthError {
				t.Errorf("authenticate(): got %v want %v", got, AuthError)
			}
		})
	})
}

func TestAuthorize_NoKeys(t *testing.T) {
	WithTempDir(func(dir string) {
		p := map[string]struct{}{"group:t": {}}

		ca := path.Join(dir, "ca")
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		pub, err := ssh.NewPublicKey(&k.PublicKey)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(ca, ssh.MarshalAuthorizedKey(pub), 0444); err != nil {
			panic(err)
		}

		WithSSHAgent(func(a agent.Agent) {
			got := authenticate(0, "", ca, p)
			if got != AuthError {
				t.Errorf("authenticate(): got %v want %v", got, AuthError)
			}
		})
	})
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name                     string
		username                 string
		args                     []string
		wantErr                  bool
		wantRequiredPrincipal    string
		wantUserCA               string
		wantAuthorizedPrincipals map[string]struct{}
	}{
		{"defaults", "testuser", []string{}, false, "testuser", defaultUserCA, map[string]struct{}{}},
		{"defaults with unknown option", "testuser", []string{"some_unknown_setting"}, false, "testuser", defaultUserCA, map[string]struct{}{}},
		{"alternate ca", "testuser", []string{"ca_file=/etc/ssh_ca.pub"}, false, "testuser", "/etc/ssh_ca.pub", map[string]struct{}{}},
		{"alternate group", "testuser", []string{"group=testgroup"}, false, "testuser", defaultUserCA, map[string]struct{}{}},
		{"no requre user", "testuser", []string{"no_require_user_principal"}, false, "", defaultUserCA, map[string]struct{}{}},
		{"list of authorized_principals", "testuser", []string{"authorized_principals=admin1,admin2,admin3"}, false, "testuser", defaultUserCA, map[string]struct{}{"admin1": {}, "admin2": {}, "admin3": {}}},
		{"missing authorized_principals_file", "testuser", []string{"authorized_principals_file=missing"}, true, "", defaultUserCA, map[string]struct{}{}},
	}

	for _, tt := range tests {
		required_principal, userCA, authorizedPrincipals, err := parseArgs(tt.username, tt.args)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("%s: succeeded unexpectededly", tt.name)
			}
		} else {
			if err != nil {
				t.Fatalf("%s: failed unexpectededly", tt.name)
			}

			if tt.wantRequiredPrincipal != required_principal {
				t.Errorf("%s: required_principal got %v want %v", tt.name, required_principal, tt.wantRequiredPrincipal)
			}

			if tt.wantUserCA != userCA {
				t.Errorf("%s: userCA got %v want %v", tt.name, userCA, tt.wantUserCA)
			}

			if !reflect.DeepEqual(tt.wantAuthorizedPrincipals, authorizedPrincipals) {
				t.Errorf("%s: authorizedPrincipals got %v want %v", tt.name, authorizedPrincipals, tt.wantAuthorizedPrincipals)
			}
		}
	}
}

func TestPamAuthorize(t *testing.T) {
	WithTempDir(func(dir string) {
		ca := path.Join(dir, "ca")
		caPamOpt := fmt.Sprintf("ca_file=%s", ca)
		principals := path.Join(dir, "principals")

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

		if err := os.WriteFile(principals, []byte("group:foober"), 0444); err != nil {
			panic(err)
		}

		WithSSHAgent(func(a agent.Agent) {
			if err := a.Add(agent.AddedKey{PrivateKey: userPriv, Certificate: c}); err != nil {
				panic(err)
			}

			uid := getUID()

			tests := []struct {
				name     string
				uid      int
				username string
				argv     []string
				want     AuthResult
			}{
				{"test missing ca file fails", uid, "foober", []string{"ca_file=missing"}, AuthError},
				{"no principal", uid, "foober", []string{caPamOpt}, AuthSuccess},
				{"test that the wrong principal fails", uid, "duber", []string{caPamOpt}, AuthError},
				{"negative test with authorized_principals pam 2option", uid, "foober", []string{caPamOpt, "authorized_principals=group:boober"}, AuthError},
				{"positive test with authorized_principals_file pam option", uid, "foober", []string{caPamOpt, fmt.Sprintf("authorized_principals_file=%s", principals)}, AuthSuccess},
				{"negative test with a bad authorized_principals_file pam option", uid, "foober", []string{caPamOpt, "authorized_principals_file=foober"}, AuthError},
				{"test that a user not in the required group passes (deprecated option)", uid, "foober", []string{caPamOpt, "group=nosuchgroup"}, AuthSuccess},
			}

			for _, tt := range tests {
				got := pamAuthenticate(tt.uid, tt.username, tt.argv)
				if got != tt.want {
					t.Errorf("authenticate(): got %v want %v", got, tt.want)
				}
			}
		})

		c2 := signedCert(userPub, signer, "user", []string{"group:foober"})
		WithSSHAgent(func(a agent.Agent) {
			if err := a.Add(agent.AddedKey{PrivateKey: userPriv, Certificate: c2}); err != nil {
				panic(err)
			}

			// test without requiring the user principal
			if r := pamAuthenticate(getUID(), "foober", []string{caPamOpt, "no_require_user_principal", "authorized_principals=group:foober"}); r != AuthSuccess {
				t.Error("authenticate() failed unexpectedly despite no_require_user_principal")
			}

			// test without requiring the user principal
			if r := pamAuthenticate(getUID(), "foober", []string{caPamOpt, "authorized_principals=group:foober"}); r != AuthError {
				t.Error("authenticate() succeeded unexpectedly despite no_require_user_principal not set")
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

func TestWithWrongCA(t *testing.T) {
	WithTempDir(func(dir string) {
		ca := path.Join(dir, "ca")
		caPamOpt := fmt.Sprintf("ca_file=%s", ca)

		// The correct CA is written to file for the pamAuthenticate function
		correctCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		correctCAPub, err := ssh.NewPublicKey(&correctCAKey.PublicKey)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(ca, ssh.MarshalAuthorizedKey(correctCAPub), 0444); err != nil {
			panic(err)
		}

		// The wrong CA is just used for signing the certificate
		wrongCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		wrongSigner, err := ssh.NewSignerFromKey(wrongCAKey)
		if err != nil {
			panic(err)
		}

		// Generate a user keypair
		userPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		userPub, err := ssh.NewPublicKey(&userPriv.PublicKey)
		if err != nil {
			panic(err)
		}

		// Sign the user keypair with the wrong CA and try to verify it
		c := signedCert(userPub, wrongSigner, "foober", []string{"group:foober"})
		WithSSHAgent(func(a agent.Agent) {
			if err := a.Add(agent.AddedKey{PrivateKey: userPriv, Certificate: c}); err != nil {
				panic(err)
			}
			got := pamAuthenticate(getUID(), "foober", []string{caPamOpt})
			if got != AuthError {
				t.Error("authenticate succeeded when it should have failed")
			}
		})
	})
}

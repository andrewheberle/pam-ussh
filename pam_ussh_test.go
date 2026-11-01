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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"reflect"
	"strings"
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

		r, err := loadValidPrincipals(slog.New(slog.DiscardHandler), p)
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
	logger, logs := newTestLogger()
	got := authenticate(logger, 0, certauth.Policy{RequiredPrincipal: "r"}, "", defaultAgentTimeout)
	if got != AuthError {
		t.Errorf("authenticate(): got %v want %v", got, AuthError)
	}
	if want := `msg="no SSH_AUTH_SOCK"`; !strings.Contains(logs.String(), want) {
		t.Errorf("logs %q do not contain %q", logs.String(), want)
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
		logger, logs := newTestLogger()
		got := authenticate(logger, 0, certauth.Policy{RequiredPrincipal: "r"}, "", defaultAgentTimeout)
		if got != AuthError {
			t.Errorf("authenticate(): got %v want %v", got, AuthError)
		}
		if want := `msg="connecting to agent failed"`; !strings.Contains(logs.String(), want) {
			t.Errorf("logs %q do not contain %q", logs.String(), want)
		}
	})
}

func TestParseArgs(t *testing.T) {
	principalsFile := path.Join(t.TempDir(), "principals")
	if err := os.WriteFile(principalsFile, []byte("group:file1\ngroup:file2\n"), 0444); err != nil {
		t.Fatal(err)
	}
	principalsFileOpt := "authorized_principals_file=" + principalsFile

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
		{"ca_file without value", "testuser", []string{"ca_file"}, true, certauth.Policy{}, ""},
		{"ca_file with empty value", "testuser", []string{"ca_file="}, true, certauth.Policy{}, ""},
		{"ca_file value containing =", "testuser", []string{"ca_file=/etc/ssh/ca=1.pub"}, false, certauth.Policy{RequiredPrincipal: "testuser"}, "/etc/ssh/ca=1.pub"},
		{"authorized_principals without value", "testuser", []string{"authorized_principals"}, true, certauth.Policy{}, ""},
		{"authorized_principals with empty value", "testuser", []string{"authorized_principals="}, true, certauth.Policy{}, ""},
		{"authorized_principals_file without value", "testuser", []string{"authorized_principals_file"}, true, certauth.Policy{}, ""},
		{"authorized_principals_file", "testuser", []string{principalsFileOpt}, false, certauth.Policy{RequiredPrincipal: "testuser", AuthorizedPrincipals: []string{"group:file1", "group:file2"}}, defaultUserCA},
		{"authorized_principals after authorized_principals_file wins", "testuser", []string{principalsFileOpt, "authorized_principals=admin1"}, false, certauth.Policy{RequiredPrincipal: "testuser", AuthorizedPrincipals: []string{"admin1"}}, defaultUserCA},
		{"authorized_principals_file after authorized_principals wins", "testuser", []string{"authorized_principals=admin1", principalsFileOpt}, false, certauth.Policy{RequiredPrincipal: "testuser", AuthorizedPrincipals: []string{"group:file1", "group:file2"}}, defaultUserCA},
		{"repeated authorized_principals last wins", "testuser", []string{"authorized_principals=admin1,admin2", "authorized_principals=admin3"}, false, certauth.Policy{RequiredPrincipal: "testuser", AuthorizedPrincipals: []string{"admin3"}}, defaultUserCA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, userCA, _, err := parseArgs(slog.New(slog.DiscardHandler), tt.username, tt.args)
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
				wantLogs []string
			}{
				{"missing ca file fails", "foober", []string{"ca_file=missing"}, AuthError,
					[]string{"level=WARN", `msg="reading CA file failed"`, "user=foober", "ca_file=missing", "err="}},
				{"valid certificate succeeds", "foober", []string{caPamOpt}, AuthSuccess,
					[]string{"level=INFO", `msg="authentication succeeded"`, "user=foober", fmt.Sprintf("uid=%d", uid), "principal=foober", "serial=1"}},
				{"wrong principal fails", "duber", []string{caPamOpt}, AuthError,
					[]string{"level=WARN", `msg="authentication failed"`, "user=duber", "err="}},
				{"bad authorized_principals_file fails", "foober", []string{caPamOpt, "authorized_principals_file=foober"}, AuthError,
					[]string{"level=WARN", `msg="could not load authorized_principals_file"`, "path=foober"}},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					logger, logs := newTestLogger()
					if got := pamAuthenticate(logger, uid, tt.username, tt.argv); got != tt.want {
						t.Errorf("pamAuthenticate(): got %v want %v", got, tt.want)
					}
					for _, want := range tt.wantLogs {
						if !strings.Contains(logs.String(), want) {
							t.Errorf("logs %q do not contain %q", logs.String(), want)
						}
					}
				})
			}
		})
	})
}

// newTestLogger returns a logger writing text records to the returned buffer.
func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
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

func TestParseArgsAgentTimeout(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    time.Duration
		wantErr bool
	}{
		{"default", []string{}, defaultAgentTimeout, false},
		{"seconds", []string{"agent_timeout=5s"}, 5 * time.Second, false},
		{"compound duration", []string{"agent_timeout=1m30s"}, 90 * time.Second, false},
		{"zero disables", []string{"agent_timeout=0"}, 0, false},
		{"last wins", []string{"agent_timeout=5s", "agent_timeout=10s"}, 10 * time.Second, false},
		{"without value", []string{"agent_timeout"}, 0, true},
		{"empty value", []string{"agent_timeout="}, 0, true},
		{"not a duration", []string{"agent_timeout=soon"}, 0, true},
		{"missing unit", []string{"agent_timeout=30"}, 0, true},
		{"negative", []string{"agent_timeout=-1s"}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, got, err := parseArgs(slog.New(slog.DiscardHandler), "testuser", tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("succeeded unexpectedly")
				}
				return
			}
			if err != nil {
				t.Fatalf("failed unexpectedly: %v", err)
			}
			if got != tt.want {
				t.Errorf("agent timeout got %v want %v", got, tt.want)
			}
		})
	}
}

// TestAgentTimeout checks that an agent which accepts the connection but
// never replies doesn't block authentication beyond the agent timeout.
func TestAgentTimeout(t *testing.T) {
	dir := t.TempDir()

	ca := path.Join(dir, "ca")
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, ssh.MarshalAuthorizedKey(pub), 0444); err != nil {
		t.Fatal(err)
	}

	sock := path.Join(dir, "agent")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	// accept connections and hold them open without replying
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				<-done
				_ = c.Close()
			}()
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", sock)

	logger, logs := newTestLogger()
	result := make(chan AuthResult, 1)
	go func() {
		result <- authenticate(logger, getUID(), certauth.Policy{RequiredPrincipal: "foober"}, ca, 100*time.Millisecond)
	}()

	select {
	case got := <-result:
		if got != AuthError {
			t.Errorf("authenticate(): got %v want %v", got, AuthError)
		}
		for _, want := range []string{`msg="authentication failed"`, "i/o timeout"} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("logs %q do not contain %q", logs.String(), want)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authenticate() did not return within 5s of a 100ms agent timeout")
	}
}

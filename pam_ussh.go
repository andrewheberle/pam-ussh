//go:build darwin || linux

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
	"bufio"
	"errors"
	"fmt"
	"log/syslog"
	"maps"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/andrewheberle/pam-ussh/internal/certauth"
	"golang.org/x/crypto/ssh/agent"
)

var (
	defaultUserCA = "/etc/ssh/ca.pub"
)

// AuthResult is the result of the authentcate function.
type AuthResult int

const (
	// AuthError is a failure.
	AuthError AuthResult = iota
	// AuthSuccess is a success.
	AuthSuccess
)

func pamLog(format string, args ...interface{}) {
	l, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, "pam-ussh")
	if err != nil {
		return
	}
	_ = l.Warning(fmt.Sprintf(format, args...))
}

// authenticate validates certs loaded on the ssh-agent at the other end of
// AuthSock.
func authenticate(uid int, policy certauth.Policy, ca string) AuthResult {
	authSock := os.Getenv("SSH_AUTH_SOCK")
	if authSock == "" {
		pamLog("no SSH_AUTH_SOCK")
		return AuthError
	}

	origEUID := os.Geteuid()
	if os.Getuid() != origEUID || origEUID == 0 {
		// Note: this only sets the euid and doesn't do anything with the egid.
		// That should be fine for most cases, but it's worth calling out.
		if !seteuid(uid) {
			pamLog("error dropping privs from %d to %d", origEUID, uid)
			return AuthError
		}
		defer func() {
			if !seteuid(origEUID) {
				pamLog("error resetting uid to %d", origEUID)
			}
		}()
	}

	conn, err := net.Dial("unix", authSock)
	if err != nil {
		pamLog("error: %v", err)
		return AuthError
	}
	defer func() {
		if err := conn.Close(); err != nil {
			pamLog("error closing agent conn: %v", err)
		}
	}()

	caBytes, err := os.ReadFile(ca)
	if err != nil {
		pamLog("error reading ca: %v", err)
		return AuthError
	}

	match, err := certauth.Verify(policy, caBytes, agent.NewClient(conn))
	if err != nil {
		pamLog("authentication failed: %v", err)
		return AuthError
	}

	pamLog("authentication succeeded for %q (cert %q, %d)", match.Principal, match.KeyID, match.Serial)
	return AuthSuccess
}

func loadValidPrincipals(principals string) (map[string]struct{}, error) {
	f, err := os.Open(principals)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			pamLog("problem closing principals file: %v", err)
		}
	}()

	p := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		p[scanner.Text()] = struct{}{}
	}
	return p, nil
}

func parseArgs(username string, argv []string) (policy certauth.Policy, userCA string, err error) {
	userCA = defaultUserCA
	authorizedPrincipals := make(map[string]struct{})
	requiredPrincipal := username

	for _, arg := range argv {
		name, value, _ := strings.Cut(arg, "=")
		switch name {
		case "ca_file", "authorized_principals", "authorized_principals_file":
			// these options require a value; fail closed rather than guess
			if value == "" {
				pamLog("option %s requires a value", name)
				return certauth.Policy{}, "", fmt.Errorf("option %s requires a value", name)
			}
		}

		switch name {
		case "ca_file":
			userCA = value
			pamLog("ca_file set to %s", userCA)
		case "group":
			pamLog("the group option is deprecated and is ignored")
		case "authorized_principals":
			for _, s := range strings.Split(value, ",") {
				authorizedPrincipals[s] = struct{}{}
			}
		case "authorized_principals_file":
			ap, err := loadValidPrincipals(value)
			if err != nil {
				pamLog("%v", err)
				return certauth.Policy{}, "", errors.New("could not load authorized_principals_file")
			}
			authorizedPrincipals = ap
		case "no_require_user_principal":
			requiredPrincipal = ""
		default:
			pamLog("unknown option: %s", name)
		}
	}

	policy = certauth.Policy{
		RequiredPrincipal:    requiredPrincipal,
		AuthorizedPrincipals: slices.Sorted(maps.Keys(authorizedPrincipals)),
	}

	return policy, userCA, nil
}

func pamAuthenticate(uid int, username string, argv []string) AuthResult {
	runtime.GOMAXPROCS(1)

	// parse args
	policy, userCA, err := parseArgs(username, argv)
	if err != nil {
		return AuthError
	}

	return authenticate(uid, policy, userCA)
}

func main() {}

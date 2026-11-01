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
	"log/slog"
	"log/syslog"
	"maps"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/andrewheberle/pam-ussh/internal/certauth"
	"golang.org/x/crypto/ssh/agent"
)

var (
	defaultUserCA = "/etc/ssh/ca.pub"
	// defaultAgentTimeout bounds the whole exchange with the ssh-agent; long
	// enough for a hardware key that waits for a touch.
	defaultAgentTimeout = 30 * time.Second
)

// AuthResult is the result of the authentcate function.
type AuthResult int

const (
	// AuthError is a failure.
	AuthError AuthResult = iota
	// AuthSuccess is a success.
	AuthSuccess
)

// newLogger returns a logger writing to syslog and a func that closes the
// syslog connection. If syslog can't be opened, log records are discarded.
func newLogger() (*slog.Logger, func()) {
	w, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, "pam-ussh")
	if err != nil {
		return slog.New(slog.DiscardHandler), func() {}
	}

	h := slog.NewTextHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// syslog adds its own timestamp
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})

	return slog.New(h), func() { _ = w.Close() }
}

// authenticate validates certs loaded on the ssh-agent at the other end of
// AuthSock.
// A non-zero agentTimeout is a deadline for the whole exchange with the agent.
func authenticate(logger *slog.Logger, uid int, policy certauth.Policy, ca string, agentTimeout time.Duration) AuthResult {
	authSock := os.Getenv("SSH_AUTH_SOCK")
	if authSock == "" {
		logger.Warn("no SSH_AUTH_SOCK")
		return AuthError
	}

	origEUID := os.Geteuid()
	if os.Getuid() != origEUID || origEUID == 0 {
		// Note: this only sets the euid and doesn't do anything with the egid.
		// That should be fine for most cases, but it's worth calling out.
		if !seteuid(uid) {
			logger.Error("dropping privileges failed", "euid", origEUID)
			return AuthError
		}
		defer func() {
			if !seteuid(origEUID) {
				logger.Error("restoring privileges failed", "euid", origEUID)
			}
		}()
	}

	conn, err := net.Dial("unix", authSock)
	if err != nil {
		logger.Warn("connecting to agent failed", "err", err)
		return AuthError
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("closing agent connection failed", "err", err)
		}
	}()

	if agentTimeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(agentTimeout)); err != nil {
			logger.Warn("setting agent deadline failed", "err", err)
			return AuthError
		}
	}

	caBytes, err := os.ReadFile(ca)
	if err != nil {
		logger.Warn("reading CA file failed", "ca_file", ca, "err", err)
		return AuthError
	}

	match, err := certauth.Verify(policy, caBytes, agent.NewClient(conn))
	if err != nil {
		logger.Warn("authentication failed", "err", err)
		return AuthError
	}

	logger.Info("authentication succeeded", "principal", match.Principal, "key_id", match.KeyID, "serial", match.Serial)
	return AuthSuccess
}

func loadValidPrincipals(logger *slog.Logger, principals string) (map[string]struct{}, error) {
	f, err := os.Open(principals)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			logger.Error("closing principals file failed", "path", principals, "err", err)
		}
	}()

	p := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		p[scanner.Text()] = struct{}{}
	}
	return p, nil
}

func parseArgs(logger *slog.Logger, username string, argv []string) (policy certauth.Policy, userCA string, agentTimeout time.Duration, err error) {
	userCA = defaultUserCA
	agentTimeout = defaultAgentTimeout
	authorizedPrincipals := make(map[string]struct{})
	requiredPrincipal := username

	for _, arg := range argv {
		name, value, _ := strings.Cut(arg, "=")
		switch name {
		case "ca_file", "authorized_principals", "authorized_principals_file", "agent_timeout":
			// these options require a value; fail closed rather than guess
			if value == "" {
				logger.Warn("option requires a value", "option", name)
				return certauth.Policy{}, "", 0, fmt.Errorf("option %s requires a value", name)
			}
		}

		switch name {
		case "ca_file":
			userCA = value
			logger.Info("ca_file set", "ca_file", userCA)
		case "group":
			logger.Warn("deprecated option ignored", "option", name)
		case "authorized_principals":
			// like authorized_principals_file, the last option given wins
			authorizedPrincipals = make(map[string]struct{})
			for s := range strings.SplitSeq(value, ",") {
				authorizedPrincipals[s] = struct{}{}
			}
		case "authorized_principals_file":
			ap, err := loadValidPrincipals(logger, value)
			if err != nil {
				logger.Warn("could not load authorized_principals_file", "path", value, "err", err)
				return certauth.Policy{}, "", 0, errors.New("could not load authorized_principals_file")
			}
			authorizedPrincipals = ap
		case "agent_timeout":
			d, err := time.ParseDuration(value)
			if err != nil || d < 0 {
				logger.Warn("invalid agent_timeout", "option", name, "value", value)
				return certauth.Policy{}, "", 0, fmt.Errorf("invalid agent_timeout %q", value)
			}
			agentTimeout = d
		case "no_require_user_principal":
			requiredPrincipal = ""
		default:
			logger.Warn("unknown option", "option", name)
		}
	}

	policy = certauth.Policy{
		RequiredPrincipal:    requiredPrincipal,
		AuthorizedPrincipals: slices.Sorted(maps.Keys(authorizedPrincipals)),
	}

	return policy, userCA, agentTimeout, nil
}

func pamAuthenticate(logger *slog.Logger, uid int, username string, argv []string) AuthResult {
	runtime.GOMAXPROCS(1)

	logger = logger.With("user", username, "uid", uid)

	// parse args
	policy, userCA, agentTimeout, err := parseArgs(logger, username, argv)
	if err != nil {
		return AuthError
	}

	return authenticate(logger, uid, policy, userCA, agentTimeout)
}

func main() {}

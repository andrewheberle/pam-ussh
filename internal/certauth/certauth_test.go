package certauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// failingSigner is an agent whose Sign always fails, so the possession proof
// can't succeed.
type failingSigner struct {
	agent.Agent
}

func (failingSigner) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	return nil, errors.New("sign refused")
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// identity is a user key pair and a certificate for it.
type identity struct {
	priv ed25519.PrivateKey
	cert *ssh.Certificate
}

// newIdentity returns a user certificate signed by ca. Each opt can modify
// the certificate before it is signed.
func newIdentity(t *testing.T, ca ssh.Signer, keyID string, principals []string, validFor time.Duration, opts ...func(*ssh.Certificate)) identity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	c := &ssh.Certificate{
		KeyId:           keyID,
		ValidPrincipals: principals,
		Key:             sshPub,
		Serial:          1,
		CertType:        ssh.UserCert,
		ValidAfter:      uint64(time.Now().Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(validFor).Unix()),
	}
	for _, opt := range opts {
		opt(c)
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return identity{priv: priv, cert: c}
}

func TestVerify(t *testing.T) {
	ca := newSigner(t)
	wrongCA := newSigner(t)
	caKeys := ssh.MarshalAuthorizedKey(ca.PublicKey())

	user := newIdentity(t, ca, "user", []string{"foober", "group:foober"}, time.Minute)
	other := newIdentity(t, ca, "other", []string{"user", "group:foober"}, time.Minute)
	wrong := newIdentity(t, wrongCA, "wrong", []string{"foober", "group:foober"}, time.Minute)
	expired := newIdentity(t, ca, "expired", []string{"foober"}, -30*time.Second)
	noPrincipals := newIdentity(t, ca, "no-principals", nil, time.Minute)
	host := newIdentity(t, ca, "host", []string{"foober", "group:foober"}, time.Minute, func(c *ssh.Certificate) {
		c.CertType = ssh.HostCert
	})

	_, plainKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		policy     Policy
		caKeys     []byte
		identities []identity
		plainKeys  bool
		failSign   bool
		want       Match
		wantErr    error
	}{
		{
			name:       "empty policy",
			policy:     Policy{},
			caKeys:     caKeys,
			identities: []identity{user},
			wantErr:    ErrEmptyPolicy,
		},
		{
			name:    "empty agent",
			policy:  Policy{RequiredPrincipal: "foober"},
			caKeys:  caKeys,
			wantErr: ErrNoCertificates,
		},
		{
			name:      "plain key only",
			policy:    Policy{RequiredPrincipal: "foober"},
			caKeys:    caKeys,
			plainKeys: true,
			wantErr:   ErrNoCertificates,
		},
		{
			name:       "required principal",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     caKeys,
			identities: []identity{user},
			want:       Match{KeyID: "user", Serial: 1, Principal: "foober"},
		},
		{
			name:       "wrong required principal",
			policy:     Policy{RequiredPrincipal: "duber"},
			caKeys:     caKeys,
			identities: []identity{user},
			wantErr:    ErrPrincipalMismatch,
		},
		{
			name:       "expired certificate",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     caKeys,
			identities: []identity{expired},
			wantErr:    ErrPrincipalMismatch,
		},
		{
			name:       "required and authorized principal",
			policy:     Policy{RequiredPrincipal: "foober", AuthorizedPrincipals: []string{"group:foober"}},
			caKeys:     caKeys,
			identities: []identity{user},
			want:       Match{KeyID: "user", Serial: 1, Principal: "group:foober"},
		},
		{
			name:       "wrong authorized principal",
			policy:     Policy{RequiredPrincipal: "foober", AuthorizedPrincipals: []string{"group:boober"}},
			caKeys:     caKeys,
			identities: []identity{user},
			wantErr:    ErrPrincipalMismatch,
		},
		{
			name:       "authorized principal without required principal",
			policy:     Policy{AuthorizedPrincipals: []string{"group:foober"}},
			caKeys:     caKeys,
			identities: []identity{other},
			want:       Match{KeyID: "other", Serial: 1, Principal: "group:foober"},
		},
		{
			name:       "authorized principal but not valid for required principal",
			policy:     Policy{RequiredPrincipal: "foober", AuthorizedPrincipals: []string{"group:foober"}},
			caKeys:     caKeys,
			identities: []identity{other},
			wantErr:    ErrPrincipalMismatch,
		},
		{
			name:       "matched principal follows certificate order",
			policy:     Policy{AuthorizedPrincipals: []string{"group:foober", "foober"}},
			caKeys:     caKeys,
			identities: []identity{user},
			want:       Match{KeyID: "user", Serial: 1, Principal: "foober"},
		},
		{
			name:       "expired certificate with authorized principal",
			policy:     Policy{AuthorizedPrincipals: []string{"foober"}},
			caKeys:     caKeys,
			identities: []identity{expired},
			wantErr:    ErrPrincipalMismatch,
		},
		{
			// the possession proof isn't attempted for a cert that fails the
			// principal checks
			name:       "wrong authorized principal is rejected before possession proof",
			policy:     Policy{RequiredPrincipal: "foober", AuthorizedPrincipals: []string{"group:boober"}},
			caKeys:     caKeys,
			identities: []identity{user},
			failSign:   true,
			wantErr:    ErrPrincipalMismatch,
		},
		{
			name:       "certificate without principals",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     caKeys,
			identities: []identity{noPrincipals},
			wantErr:    ErrNoPrincipals,
		},
		{
			name:       "certificate without principals and authorized principals",
			policy:     Policy{AuthorizedPrincipals: []string{"group:foober"}},
			caKeys:     caKeys,
			identities: []identity{noPrincipals},
			wantErr:    ErrNoPrincipals,
		},
		{
			name:       "host certificate",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     caKeys,
			identities: []identity{host},
			wantErr:    ErrNotUserCertificate,
		},
		{
			name:       "host certificate and authorized principals",
			policy:     Policy{RequiredPrincipal: "foober", AuthorizedPrincipals: []string{"group:foober"}},
			caKeys:     caKeys,
			identities: []identity{host},
			wantErr:    ErrNotUserCertificate,
		},
		{
			name:       "rejected host and principal-less certificates then valid certificate",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     caKeys,
			identities: []identity{host, noPrincipals, user},
			want:       Match{KeyID: "user", Serial: 1, Principal: "foober"},
		},
		{
			name:       "wrong CA",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     caKeys,
			identities: []identity{wrong},
			wantErr:    ErrUnknownAuthority,
		},
		{
			name:       "CA with no valid keys",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     []byte("not a key\n"),
			identities: []identity{user},
			wantErr:    ErrNoValidCA,
		},
		{
			name:       "empty CA",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     []byte{},
			identities: []identity{user},
			wantErr:    ErrNoValidCA,
		},
		{
			name:    "empty CA reported before empty agent",
			policy:  Policy{RequiredPrincipal: "foober"},
			caKeys:  []byte{},
			wantErr: ErrNoValidCA,
		},
		{
			name:       "CA with a bad line before a good key",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     append([]byte("not a key\n"), caKeys...),
			identities: []identity{user},
			want:       Match{KeyID: "user", Serial: 1, Principal: "foober"},
		},
		{
			name:       "rejected certificate then valid certificate",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     caKeys,
			identities: []identity{wrong, user},
			want:       Match{KeyID: "user", Serial: 1, Principal: "foober"},
		},
		{
			name:       "possession proof fails",
			policy:     Policy{RequiredPrincipal: "foober"},
			caKeys:     caKeys,
			identities: []identity{user},
			failSign:   true,
			wantErr:    ErrProofFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring := agent.NewKeyring()
			for _, id := range tt.identities {
				if err := keyring.Add(agent.AddedKey{PrivateKey: id.priv, Certificate: id.cert}); err != nil {
					t.Fatal(err)
				}
			}
			if tt.plainKeys {
				if err := keyring.Add(agent.AddedKey{PrivateKey: plainKey}); err != nil {
					t.Fatal(err)
				}
			}

			a := keyring
			if tt.failSign {
				a = failingSigner{keyring}
			}

			got, err := Verify(tt.policy, tt.caKeys, a)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Verify() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

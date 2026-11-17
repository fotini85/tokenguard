package token_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fotini85/tokenguard/internal/apperr"
	"github.com/fotini85/tokenguard/internal/token"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// clock pins the codec to one instant, so expiry is something the test
// states rather than something it waits for.
func clock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func accessClaims() token.Claims {
	return token.Claims{
		Kind:      token.KindAccess,
		IssuedAt:  t0,
		ExpiresAt: t0.Add(10 * time.Minute),
		UserID:    "42",
		SessionID: "wq8Zk3vNc1pQrS7t",
	}
}

// mustSign fails the test rather than returning an error, so the tests
// below read as the thing they are checking and not as error handling.
func mustSign(t *testing.T, c *token.Codec, cl token.Claims) string {
	t.Helper()
	raw, err := c.Sign(cl)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return raw
}

func TestSignVerifyRoundTrip(t *testing.T) {
	c := token.NewCodec(key(1), clock(t0))
	want := accessClaims()

	got, err := c.Verify(mustSign(t, c, want), token.KindAccess)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if got.Kind != want.Kind {
		t.Errorf("Kind = %v, want %v", got.Kind, want.Kind)
	}
	if got.UserID != want.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, want.UserID)
	}
	if got.SessionID != want.SessionID {
		t.Errorf("SessionID = %q, want %q", got.SessionID, want.SessionID)
	}

	// Equal, not ==. Times go over the wire as Unix seconds, so what
	// comes back is a different time.Time describing the same instant:
	// another location, and no monotonic reading.
	if !got.IssuedAt.Equal(want.IssuedAt) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, want.IssuedAt)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
}

// The shape is v1.<payload>.<signature>. Tests that damage one part
// need the other two intact.
func parts(t *testing.T, raw string) (prefix, payload, sig string) {
	t.Helper()
	p := strings.Split(raw, ".")
	if len(p) != 3 {
		t.Fatalf("token has %d parts, want 3: %q", len(p), raw)
	}
	return p[0], p[1], p[2]
}

// flip changes the last character of s to a different one, so the
// result is the same length and still valid base64url.
func flip(s string) string {
	last := s[len(s)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	return s[:len(s)-1] + string(repl)
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	c := token.NewCodec(key(1), clock(t0))
	prefix, payload, sig := parts(t, mustSign(t, c, accessClaims()))

	_, err := c.Verify(prefix+"."+payload+"."+flip(sig), token.KindAccess)
	if got := apperr.KindOf(err); got != apperr.KindBadSignature {
		t.Errorf("Kind = %v, want %v", got, apperr.KindBadSignature)
	}
}

// A changed payload is reported as a bad signature, not as malformed,
// and that ordering is the point. The signature covers the payload, so
// it is checked first and nothing inside is ever parsed unless it was
// us who wrote it. Parsing first would mean running the JSON decoder
// over whatever a stranger sent.
func TestVerifyRejectsTamperedPayloadBeforeParsingIt(t *testing.T) {
	c := token.NewCodec(key(1), clock(t0))
	prefix, payload, sig := parts(t, mustSign(t, c, accessClaims()))

	_, err := c.Verify(prefix+"."+flip(payload)+"."+sig, token.KindAccess)
	if got := apperr.KindOf(err); got != apperr.KindBadSignature {
		t.Errorf("Kind = %v, want %v", got, apperr.KindBadSignature)
	}
}

// A token minted under one key must mean nothing under another. This is
// what makes rotating the signing key sign everybody out.
func TestVerifyRejectsAnotherKeysToken(t *testing.T) {
	signer := token.NewCodec(key(1), clock(t0))
	verifier := token.NewCodec(key(2), clock(t0))

	_, err := verifier.Verify(mustSign(t, signer, accessClaims()), token.KindAccess)
	if got := apperr.KindOf(err); got != apperr.KindBadSignature {
		t.Errorf("Kind = %v, want %v", got, apperr.KindBadSignature)
	}
}

// The signature is valid and the token is still refused, because it was
// minted for something else. Without this check an anonymous token —
// which anyone can ask for — would pass as proof of identity, and
// anyone could be anyone. It is the same hole as JWT's "alg: none".
func TestVerifyRejectsWrongKind(t *testing.T) {
	c := token.NewCodec(key(1), clock(t0))

	anon := token.Claims{
		Kind:      token.KindAnon,
		IssuedAt:  t0,
		ExpiresAt: t0.Add(10 * time.Minute),
	}

	_, err := c.Verify(mustSign(t, c, anon), token.KindAccess)
	if got := apperr.KindOf(err); got != apperr.KindWrongType {
		t.Errorf("Kind = %v, want %v", got, apperr.KindWrongType)
	}
}

func TestVerifyExpiry(t *testing.T) {
	signer := token.NewCodec(key(1), clock(t0))
	raw := mustSign(t, signer, accessClaims()) // expires at t0+10m

	tests := []struct {
		name string
		at   time.Time
		want apperr.Kind
	}{
		{"well before expiry", t0.Add(time.Minute), apperr.KindInternal},
		{"one second before", t0.Add(10*time.Minute - time.Second), apperr.KindInternal},
		// The comparison is now >= exp, so the moment of expiry is
		// already too late. A token is valid up to its expiry, not
		// through it.
		{"exactly at expiry", t0.Add(10 * time.Minute), apperr.KindExpired},
		{"after expiry", t0.Add(11 * time.Minute), apperr.KindExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := token.NewCodec(key(1), clock(tt.at)).Verify(raw, token.KindAccess)

			// KindInternal is what KindOf answers for a nil error, so
			// the valid cases read as "no failure of any kind".
			if got := apperr.KindOf(err); got != tt.want {
				t.Errorf("Kind = %v (err = %v), want %v", got, err, tt.want)
			}
			if tt.want == apperr.KindInternal && err != nil {
				t.Errorf("Verify() error = %v, want nil", err)
			}
		})
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	c := token.NewCodec(key(1), clock(t0))

	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"no separator", "notatoken"},
		{"prefix only", "v1."},
		{"two parts", "v1.eyJrIjoyfQ"},
		{"unknown version", "v2.eyJrIjoyfQ.c2ln"},
		{"signature not base64", "v1.eyJrIjoyfQ.!!!!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Verify(tt.raw, token.KindAccess)
			if got := apperr.KindOf(err); got != apperr.KindMalformed {
				t.Errorf("Kind = %v, want %v", got, apperr.KindMalformed)
			}
		})
	}
}

// Every one of these answers 401 through apperr.HTTPStatus, so a caller
// cannot tell a forged token from an expired one from a mistyped one.
// The kinds exist for the logs, not for the response.
func TestVerifyFailuresAreIndistinguishableToTheCaller(t *testing.T) {
	c := token.NewCodec(key(1), clock(t0.Add(time.Hour)))
	prefix, payload, sig := parts(t, mustSign(t, c, accessClaims()))

	raws := map[string]string{
		"expired":       prefix + "." + payload + "." + sig,
		"bad signature": prefix + "." + payload + "." + flip(sig),
		"malformed":     "rubbish",
	}

	for name, raw := range raws {
		_, err := c.Verify(raw, token.KindAccess)
		if err == nil {
			t.Fatalf("%s: Verify() succeeded, want failure", name)
		}
		if status, msg := apperr.HTTPStatus(err); status != 401 || msg != "unauthorized" {
			t.Errorf("%s leaked: got %d %q", name, status, msg)
		}
	}
}

// NewCodec keeps its own copy. A caller that reuses or wipes the slice
// it passed in — which is the responsible thing to do with key material
// — must not quietly invalidate every token already issued.
func TestNewCodecCopiesTheKey(t *testing.T) {
	k := key(1)
	c := token.NewCodec(k, clock(t0))
	raw := mustSign(t, c, accessClaims())

	for i := range k {
		k[i] = 0
	}

	if _, err := c.Verify(raw, token.KindAccess); err != nil {
		t.Errorf("Verify() error = %v: the codec is reading the caller's slice", err)
	}
}

// Short keys are refused at construction. HMAC-SHA256 accepts any
// length, so nothing downstream would complain about an eight-byte key
// — it would simply be guessable, and every token forgeable.
func TestNewCodecRejectsShortKeys(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31} {
		t.Run(fmt.Sprintf("%d bytes", n), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("NewCodec() accepted a %d-byte key", n)
				}
			}()
			token.NewCodec(make([]byte, n), clock(t0))
		})
	}
}

func TestNewCodecAcceptsExactlyThirtyTwo(t *testing.T) {
	token.NewCodec(make([]byte, 32), clock(t0))
}

// An access token with no user is not a token, it is a hole: whatever
// reads the claims would treat the empty string as an identity.
func TestSignRefusesAccessTokenWithoutUser(t *testing.T) {
	c := token.NewCodec(key(1), clock(t0))

	cl := accessClaims()
	cl.UserID = ""

	if _, err := c.Sign(cl); err == nil {
		t.Error("Sign() accepted an access token with no user id")
	}
}

// Two tokens signed a second apart must differ, or a signature captured
// once would verify forever against a replayed body.
func TestSignIsNotConstant(t *testing.T) {
	c := token.NewCodec(key(1), clock(t0))

	first := mustSign(t, c, accessClaims())

	later := accessClaims()
	later.IssuedAt = t0.Add(time.Second)
	second := mustSign(t, c, later)

	if first == second {
		t.Error("two tokens with different claims produced the same string")
	}
}

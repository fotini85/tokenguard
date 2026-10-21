package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/fotini85/tokenguard/internal/apperr"
)

const prefix = "v1"

var b64 = base64.RawURLEncoding

type Codec struct {
	key []byte
	now func() time.Time
}

func NewCodec(key []byte, now func() time.Time) *Codec {
	if len(key) < 32 {
		panic("token : key must be at least 32  bytes")
	}
	if now == nil {
		now = time.Now
	}

	k := make([]byte, len(key))
	copy(k, key)
	return &Codec{key: k, now: now}
}

// wire is the JSON shape. Times are Unix seconds rather than RFC3339
// because they are shorter and unambiguous, and because time.Time
// round-trips through JSON without its monotonic reading anyway.
type wire struct {
	K   Kind    `json:"k"`
	Iat int64   `json:"iat"`
	Exp int64   `json:"exp"`
	Uid string  `json:"uid,omitempty"`
	Sid string  `json:"sid,omitempty"`
	Av  float64 `json:"av,omitempty"`
	Ls  int64   `json:"ls,omitempty"`
}

//sign claims

func (c *Codec) Sign(cl Claims) (string, error) {
	const op = "token.Sign"

	payload, err := json.Marshal(wire{
		K:   cl.Kind,
		Iat: cl.IssuedAt.Unix(),
		Exp: cl.ExpiresAt.Unix(),
		Uid: cl.UserID,
		Sid: cl.SessionID,
		Av:  cl.Available,
		Ls:  unixOrZero(cl.LastSeen),
	})

	if cl.Kind == KindAccess && cl.UserID == "" {
		return "", apperr.E(op, apperr.KindInternal,
			errors.New("access token needs a user id"))
	}
	if err != nil {
		return "", apperr.E(op, apperr.KindInternal, err)
	}

	body := prefix + "." + b64.EncodeToString(payload)

	return body + "." + b64.EncodeToString(c.mac(body)), nil
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOrZero(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)

}
func (c *Codec) mac(body string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(body))
	return m.Sum(nil)
}

// checking sigrature, kind and expire->claims
func (c *Codec) Verify(raw string, want Kind) (Claims, error) {
	const op = "token.Verify"

	i := strings.LastIndexByte(raw, '.')
	if i < 0 {
		return Claims{}, apperr.E(op, apperr.KindMalformed, nil)
	}
	body, sig := raw[:i], raw[i+1:]

	if !strings.HasPrefix(body, prefix+".") {
		return Claims{}, apperr.E(op, apperr.KindMalformed, nil)
	}

	got, err := b64.DecodeString(sig)
	if err != nil {
		return Claims{}, apperr.E(op, apperr.KindMalformed, err)
	}

	if !hmac.Equal(got, c.mac(body)) {
		return Claims{}, apperr.E(op, apperr.KindBadSignature, nil)
	}

	//now is the correct time to parse the sig
	payload, err := b64.DecodeString(body[len(prefix)+1:])
	if err != nil {
		return Claims{}, apperr.E(op, apperr.KindMalformed, err)
	}

	var w wire
	if err := json.Unmarshal(payload, &w); err != nil {
		return Claims{}, apperr.E(op, apperr.KindMalformed, err)

	}
	if w.K != want {
		return Claims{}, apperr.E(op, apperr.KindWrongType, nil)
	}
	if c.now().Unix() >= w.Exp {
		return Claims{}, apperr.E(op, apperr.KindExpired, nil)
	}
	return Claims{
		Kind:      w.K,
		IssuedAt:  time.Unix(w.Iat, 0),
		ExpiresAt: time.Unix(w.Exp, 0),
		UserID:    w.Uid,
		SessionID: w.Sid,
		Available: w.Av,
		LastSeen:  timeOrZero(w.Ls),
	}, nil
}

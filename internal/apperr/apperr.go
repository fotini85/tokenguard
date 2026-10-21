package apperr

import (
	"errors"
	"fmt"
	"net/http"
)

type Kind uint8

const (
	KindInternal Kind = iota
	KindMalformed
	KindBadSignature
	KindExpired
	KindWrongType
	KindRevoked
	KindRateLimited
	KindConflict
	KindNotFound
)

func (k Kind) String() string {
	switch k {
	case KindMalformed:
		return "malformed"
	case KindBadSignature:
		return "bad signature"
	case KindExpired:
		return "expired"
	case KindWrongType:
		return "wrong token type"
	case KindRevoked:
		return "revoked"
	case KindRateLimited:
		return "rate limited"
	case KindConflict:
		return "conflict"
	case KindNotFound:
		return "not found"
	default:
		return "internal"
	}
}

type Error struct {
	Kind Kind
	Op   string
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Op, e.Kind)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func E(op string, kind Kind, err error) *Error {
	return &Error{Kind: kind, Op: op, Err: err}
}

func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindInternal
}

func HTTPStatus(err error) (int, string) {
	switch KindOf(err) {
	case KindMalformed, KindBadSignature, KindExpired, KindWrongType, KindRevoked:
		return http.StatusUnauthorized, "unauthorized"
	case KindRateLimited:
		return http.StatusTooManyRequests, "rate limit exceeded"
	case KindNotFound:
		return http.StatusNotFound, "not found"
	case KindConflict:
		return http.StatusConflict, "conflict"
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

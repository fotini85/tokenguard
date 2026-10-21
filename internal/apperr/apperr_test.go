package apperr_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/fotini85/tokenguard/internal/apperr"
)

func TestKindOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want apperr.Kind
	}{
		{"nil", nil, apperr.KindInternal},
		{"plain", errors.New("boom"), apperr.KindInternal},
		{"direct", apperr.E("op", apperr.KindExpired, nil), apperr.KindExpired},
		{
			"wrapped twice",
			apperr.E("outer", apperr.KindRevoked,
				apperr.E("inner", apperr.KindExpired, nil)),
			apperr.KindRevoked,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apperr.KindOf(tt.err); got != tt.want {
				t.Errorf("KindOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTPStatus_AuthFailuresAreIndistinguishable(t *testing.T) {
	kinds := []apperr.Kind{
		apperr.KindMalformed,
		apperr.KindBadSignature,
		apperr.KindExpired,
		apperr.KindWrongType,
		apperr.KindRevoked,
	}
	for _, k := range kinds {
		status, msg := apperr.HTTPStatus(apperr.E("op", k, nil))
		if status != http.StatusUnauthorized || msg != "unauthorized" {
			t.Errorf("kind %v leaked: got %d %q", k, status, msg)
		}
	}
}

func TestError_UnwrapChain(t *testing.T) {
	sentinel := errors.New("db down")
	err := apperr.E("postgres.Insert", apperr.KindInternal, sentinel)
	if !errors.Is(err, sentinel) {
		t.Error("errors.Is failed to find wrapped sentinel")
	}
}

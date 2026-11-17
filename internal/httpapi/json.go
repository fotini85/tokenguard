package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fotini85/tokenguard/internal/apperr"
	"github.com/fotini85/tokenguard/internal/domain"
)

// decode reads a JSON body into dst.
//
// MaxBytesReader caps the read at the connection level, so an oversized
// body is cut off rather than buffered. DisallowUnknownFields rejects
// anything that is not in the struct: a client sending "passwrod" gets
// told, instead of silently registering with an empty password.
func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	const op = "httpapi.decode"

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return apperr.E(op, apperr.KindMalformed, err)
		}
		return apperr.E(op, apperr.KindMalformed, err)
	}

	// A second value in the body means the client sent something other
	// than one object — two concatenated payloads, or trailing junk.
	if dec.More() {
		return apperr.E(op, apperr.KindMalformed,
			errors.New("body must contain a single JSON object"))
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Nothing to do if this fails: the status is already on the wire
	// and the connection is probably gone.
	_ = json.NewEncoder(w).Encode(v)
}

func writeTokens(w http.ResponseWriter, t domain.Tokens) {
	writeJSON(w, http.StatusOK, tokenPair{
		AccessToken:  t.Access,
		RefreshToken: t.Refresh,
		// Unix seconds rather than RFC3339: shorter, unambiguous, and
		// every client can compare it to its own clock without parsing.
		ExpiresAt: t.ExpiresAt.Unix(),
	})
}

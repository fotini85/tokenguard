// Package httpapi exposes the auth endpoints over HTTP.
//
// The handlers are deliberately thin: read JSON, call the domain, write
// JSON. Anything resembling a business rule belongs in domain, where it
// can be tested without a server.
package httpapi

import (
	"context"
	"net/http"

	"github.com/fotini85/tokenguard/internal/apperr"
	"github.com/fotini85/tokenguard/internal/authmw"
	"github.com/fotini85/tokenguard/internal/domain"
)

// maxBody caps how much JSON a caller may send.
//
// Without it, one request can make the server read gigabytes into
// memory before anything rejects it. 4KB is far more than any of these
// endpoints needs — an email and a password — and the reader fails the
// request rather than truncating it.
const maxBody = 4 << 10

// Auth is the part of domain.AuthService these handlers use.
//
// Declared here rather than taking the concrete type: handlers that
// state what they need are testable against a fake in a few lines.
type Auth interface {
	Login(ctx context.Context, email, password string) (domain.Tokens, error)
	Refresh(ctx context.Context, refresh string) (domain.Tokens, error)
	Revoke(ctx context.Context, sessionID string) error
}

// Registrar is the part of domain.Registry these handlers use.
type Registrar interface {
	Register(ctx context.Context, email, password string) (int64, error)
}

type Handlers struct {
	auth Auth
	reg  Registrar
}

func New(auth Auth, reg Registrar) *Handlers {
	if auth == nil || reg == nil {
		panic("httpapi: auth and registrar are required")
	}
	return &Handlers{auth: auth, reg: reg}
}

// Routes returns the auth endpoints.
//
// Go 1.22's router matches on method as well as path, so a GET to a
// POST-only route gets 405 without any code here.
func (h *Handlers) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", h.register)
	mux.HandleFunc("POST /auth/login", h.login)
	mux.HandleFunc("POST /auth/refresh", h.refresh)
	mux.HandleFunc("POST /auth/logout", h.logout)
	return mux
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

func (h *Handlers) register(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if err := decode(w, r, &in); err != nil {
		writeErr(w, err)
		return
	}

	id, err := h.reg.Register(r.Context(), in.Email, in.Password)
	if err != nil {
		writeErr(w, err)
		return
	}

	// Registering does not sign anyone in. The two are separate
	// decisions, and a caller who wants both calls login next.
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handlers) login(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if err := decode(w, r, &in); err != nil {
		writeErr(w, err)
		return
	}

	tokens, err := h.auth.Login(r.Context(), in.Email, in.Password)
	if err != nil {
		writeErr(w, err)
		return
	}

	writeTokens(w, tokens)
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) refresh(w http.ResponseWriter, r *http.Request) {
	var in refreshRequest
	if err := decode(w, r, &in); err != nil {
		writeErr(w, err)
		return
	}

	tokens, err := h.auth.Refresh(r.Context(), in.RefreshToken)
	if err != nil {
		writeErr(w, err)
		return
	}

	writeTokens(w, tokens)
}

// logout ends the session the caller is currently on.
//
// The session id comes from the verified access token rather than from
// the request body: taking it from the body would let anyone end
// anyone else's session by guessing an id.
//
// This route must be mounted behind the auth middleware. MustIdentity
// panics if it is not, which is the right outcome — a zero Identity
// looks exactly like a legitimate anonymous caller, so failing quietly
// would turn a wiring mistake into an authorisation hole.
func (h *Handlers) logout(w http.ResponseWriter, r *http.Request) {
	id := authmw.MustIdentity(r.Context())
	if !id.Authenticated {
		writeErr(w, apperr.E("httpapi.logout", apperr.KindBadSignature, nil))
		return
	}

	if err := h.auth.Revoke(r.Context(), id.SessionID); err != nil {
		writeErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

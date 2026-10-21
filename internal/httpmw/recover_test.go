package httpmw_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fotini85/tokenguard/internal/httpmw"
)

func TestRecover(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	h := httpmw.Recover(log)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			panic("boom")
		}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// If Recover does not work, this test panics and the whole run dies.
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRecoverPassesAbortHandlerThrough(t *testing.T) {
	h := httpmw.Recover(discardLogger())(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			panic(http.ErrAbortHandler)
		}))

	defer func() {
		v := recover()
		if v != http.ErrAbortHandler {
			t.Errorf("recovered %v, want ErrAbortHandler", v)
		}
	}()

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	t.Error("ServeHTTP returned instead of panicking")
}

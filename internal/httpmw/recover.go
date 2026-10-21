// Package httpmw holds HTTP middleware that is not specific to
// authentication: recovery, logging, and chaining.
package httpmw

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				if v == http.ErrAbortHandler {
					panic(v)
				}

				log.Error("panic recovered",
					"panic", v,
					"stack", string(debug.Stack()),
					"method", r.Method,
					"path", r.URL.Path)

				http.Error(w, "internal error", http.StatusInternalServerError)
			}()
			next.ServeHTTP(w, r)
		})
	}
}

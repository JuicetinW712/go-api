package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log message
				slog.Error("Server Error",
					"time", time.Now(),
					"path", r.URL.Path,
					"error", err,
					"stack", string(debug.Stack()),
				)

				// Return error message to client
				err := http.StatusInternalServerError
				http.Error(w, "Internal Server Error", err)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

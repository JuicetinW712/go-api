package middleware

import (
	"context"
	"go-api/internal/auth"
	"net/http"
	"strings"
)

type contextKey string

const ClaimsContextKey contextKey = "claims"

func AuthMiddleware(authService *auth.AuthService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := r.Header.Get("Authorization")

			// No JWT
			if tokenStr == "" || !strings.HasPrefix(tokenStr, "Bearer: ") {
				http.Error(w, "Request did not include JWT token", http.StatusUnauthorized)
				return
			}

			tokenStr = strings.TrimPrefix(tokenStr, "Bearer: ")

			// Parse JWT
			claims, err := authService.ValidateToken(tokenStr)
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, ClaimsContextKey, claims)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

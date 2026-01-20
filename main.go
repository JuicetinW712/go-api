package app

import (
	"go-api/internal/auth"
	"go-api/internal/handlers"
	"go-api/internal/middleware"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewServer(
	// logger *Logger
	// config *Config
	userRepo *repositories.UserRepository,
) http.Handler {
	// Add services and handlers
	userService := services.NewUserService(userRepo)
	authService := auth.NewAuthService("issuer", "key")
	authMiddleware := middleware.AuthMiddleware(authService)

	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) {
		r.Route("/auth", auth.AuthHandler)
	})

	r.Route("/api", func(r chi.Router) {
		r.Route("/auth", auth.AuthHandler)
	})

	mux := http.NewServeMux()

	mux.Handle("/api/users", handlers.NewUserHandler(userService))

	// Add middlware
	var handler http.Handler = mux
	handler = middleware.RecoveryMiddleware(handler)
	handler = middleware.LoggingMiddleware(handler)
	handler = authMiddleware(handler)
	// handler = middleware.CORSMiddleware(handler)
	// handler = middleware.RateLimitMiddleware(handler)
	return handler
}

func main() {
	// server := NewServer()
	http.ListenAndServe(":8080", nil)
}

package handlers

// import (
// 	"encoding/json"
// 	"net/http"

// 	"github.com/go-chi/chi/v5"
// )

// type AuthHandler struct {
// 	authService IAuthService
// }

// func NewAuthHandler(authService IAuthService) *AuthHandler {
// 	return &AuthHandler{authService}
// }

// func (auth *AuthHandler) Routes() chi.Router {
// 	r := chi.NewRouter()

// 	r.Get("/login", auth.Login)
// 	r.Get("/register", auth.Register)

// 	return r
// }

// func (auth *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
// 	var loginInfo LoginInfo
// 	if err := json.NewDecoder(r.Body).Decode(&loginInfo); err != nil {
// 		http.Error(w, "Invalid request body", http.StatusBadRequest)
// 	}

// 	auth.authService.Login(loginInfo)
// }

// func (auth *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {

// }

// func (auth *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {

// }

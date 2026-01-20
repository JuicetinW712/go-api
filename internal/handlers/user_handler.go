package handlers

import (
	"go-api/internal/user"
	"net/http"
)

// type UserService struct {
// 	repo *repositories.UserRepository
// }

// func (us *UserService) GetUser(id string) (string, error) {
// 	return "User: " + id, nil
// }

type UserHandler struct {
	userService *user.UserService
}

func NewUserHandler(userService *user.UserService) *UserHandler {
	return &UserHandler{userService}
}

func (uh *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// switch r.Method
	
}

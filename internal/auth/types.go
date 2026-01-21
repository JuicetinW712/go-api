package auth

import "github.com/golang-jwt/jwt/v5"

type UserClaims struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`

	jwt.RegisteredClaims
}

type LoginInfo struct {
	Username string
	Password string
	Email    string
}

type AuthUser struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type TokenResponse struct {
	AccessToken  string
	RefreshToken string
}

type IAuthService interface {
	Login(username string, password string) (TokenResponse, error)
	Register(info LoginInfo) error
	RefreshToken(tokenStr string) (string, error)
	GetUserInfo(tokenStr string) (User, error)
}

type IAuthRepo interface {
	CreateUser(user AuthUser) error
	GetUser(username string) (AuthUser, error)
}

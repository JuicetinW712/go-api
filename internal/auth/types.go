package auth

import "github.com/golang-jwt/jwt/v5"

type UserClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type LoginInfo struct {
	Username string
	Password string
}

type AuthUser struct {
	ID       string
	Username string
}

type TokenResponse struct {
	AccessToken  string
	RefreshToken string
}

type IAuthService interface {
	Login(loginInfo LoginInfo) string
	Register(loginInfo LoginInfo) string
	GenerateToken(username string, role string) (string, error)
	RefreshToken(tokenStr string)
	ValidateToken(tokenStr string) (*UserClaims, error)
}

type IAuthRepo interface {
	RegisterAuthUser(loginInfo LoginInfo)
	ValidateAuthUser(loginInfo LoginInfo) bool
}

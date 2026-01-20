package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthService struct {
	issuer    string
	secretKey string
	authRepo  IAuthRepo
}

func NewAuthService(issuer string, secretKey string, authRepo IAuthRepo) *AuthService {
	return &AuthService{
		issuer,
		secretKey,
		authRepo,
	}
}

func (auth *AuthService) Login(loginInfo LoginInfo) TokenResponse {
	// loginInfo.Password =

	// 	auth.authRepo.ValidateAuthUser(loginInfo)
	return TokenResponse{}
}

func (auth *AuthService) Register(loginInfo LoginInfo) bool {

}

func (auth *AuthService) GenerateAccessToken(user AuthUser) (string, error) {
	claims := UserClaims{
		Username: user.Username,
		Role:     "role",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.Username,
			Issuer:    auth.issuer,
			Audience:  jwt.ClaimStrings{"role"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(3 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(auth.secretKey)
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func (auth *AuthService) RefreshToken(refreshTkn string) {

}

func (auth *AuthService) ValidateToken(tokenStr string) (*UserClaims, error) {
	claims := &UserClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(tk *jwt.Token) (any, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return auth.secretKey, nil
	},
		jwt.WithIssuer(auth.issuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil || !token.Valid {
		return nil, err
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, fmt.Errorf("expired JWT")
	}

	return claims, nil
}

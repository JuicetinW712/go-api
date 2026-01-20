package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	issuer    string
	secretKey string
	repo      IAuthRepo
}

func NewAuthService(issuer string, secretKey string, authRepo IAuthRepo) *AuthService {
	return &AuthService{issuer, secretKey, authRepo}
}

func (auth *AuthService) Login(username string, password string) (TokenResponse, error) {
	// Get user from db
	user, err := auth.repo.GetUser(username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return TokenResponse{}, ErrInvalidCredentials
		}
		return TokenResponse{}, fmt.Errorf("getting user: %w", err)
	}

	// Validate password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return TokenResponse{}, ErrInvalidCredentials
	}

	// Generate tokens
	return auth.generateAccessAndRefreshTokens(user)
}

func (auth *AuthService) Register(info LoginInfo) error {
	// Encrypt password
	data := []byte(info.Password)
	encryptedPassword, err := bcrypt.GenerateFromPassword(data, bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	// Create user
	user := AuthUser{
		ID:           uuid.New().String(),
		Username:     info.Username,
		Email:        info.Email,
		PasswordHash: string(encryptedPassword),
	}
	err = auth.repo.CreateUser(user)

	if err != nil {
		if errors.Is(err, errDbDuplicateKey) {
			return ErrConflict
		}
		return fmt.Errorf("creating auth user: %w", err)
	}

	return nil
}

func (auth *AuthService) RefreshToken(tokenStr string) {
	// Validate and parse the existing token

	// Generate a new token with extended expiration
}

func (auth *AuthService) GetUserInfo(tokenStr string) (User, error) {
	claims := &UserClaims{}

	// Validates HMAC signature, issuer, and expiration time
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(tk *jwt.Token) (any, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return User{}, jwt.ErrSignatureInvalid
		}
		return auth.secretKey, nil
	},
		jwt.WithIssuer(auth.issuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil || !token.Valid {
		return User{}, err
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		return User{}, fmt.Errorf("expired JWT")
	}

	return User{
		ID:       claims.ID,
		Username: claims.Username,
		Email:    claims.Email,
	}, nil
}

func (auth *AuthService) generateToken(user AuthUser, duration time.Duration) (string, error) {
	claims := UserClaims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.Username,
			Issuer:    auth.issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
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

func (auth *AuthService) generateAccessAndRefreshTokens(user AuthUser) (TokenResponse, error) {
	accessToken, err := auth.generateToken(user, 3*time.Hour)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("generating access token: %w", err)
	}

	refreshToken, err := auth.generateToken(user, 7*24*time.Hour)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("generating refresh token: %w", err)
	}

	return TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

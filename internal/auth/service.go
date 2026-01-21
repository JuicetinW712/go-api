package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var REFRESH_TOKEN_DURATION = 7 * 24 * time.Hour
var ACCESS_TOKEN_DURATION = 3 * time.Hour

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
	tokens, err := auth.generateAccessAndRefreshTokens(User{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
	})
	if err != nil {
		return TokenResponse{}, fmt.Errorf("generating tokens: %w", err)
	}

	return tokens, nil
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

func (auth *AuthService) RefreshToken(tokenStr string) (TokenResponse, error) {
	// Validate and parse the existing token
	user, err := auth.GetUser(tokenStr)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("validating token: %w", err)
	}

	// Generate a new token with extended expiration
	token, err := auth.generateAccessAndRefreshTokens(user)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("generating new token: %w", err)
	}

	return token, nil
}

func (auth *AuthService) GetUser(tokenStr string) (User, error) {
	claims := &UserClaims{}

	// Validates HMAC signature, issuer, and expiration time
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(tk *jwt.Token) (any, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tk.Header["alg"])
		}
		return auth.secretKey, nil
	},
		jwt.WithIssuer(auth.issuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil || !token.Valid || claims.ExpiresAt.Time.Before(time.Now()) {
		return User{}, ErrInvalidCredentials
	}

	return User{
		ID:       claims.ID,
		Username: claims.Username,
		Email:    claims.Email,
	}, nil
}

func (auth *AuthService) generateToken(user User, duration time.Duration) (string, error) {
	claims := UserClaims{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
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

func (auth *AuthService) generateAccessAndRefreshTokens(user User) (TokenResponse, error) {
	accessToken, err := auth.generateToken(user, ACCESS_TOKEN_DURATION)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("generating access token: %w", err)
	}

	refreshToken, err := auth.generateToken(user, REFRESH_TOKEN_DURATION)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("generating refresh token: %w", err)
	}

	return TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

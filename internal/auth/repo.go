package auth

import (
	"database/sql"
)

type AuthRepository struct{
	db *sql.DB
}

func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{db}
}

// TODO - implement
func (ar *AuthRepository) CreateUser(user AuthUser) error {
	return nil
}

// TODO - implement
func (ar *AuthRepository) GetUser(username string) (AuthUser, error) {
	return AuthUser{}, nil
}

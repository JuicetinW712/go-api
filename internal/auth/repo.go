package auth

import (
	"database/sql"
	"fmt"
)

type AuthRepository struct {
	db *sql.DB
}

func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{db}
}

// TODO - implement
func (ar *AuthRepository) CreateUser(user AuthUser) error {
	query := `
		INSERT INTO users (id, username, email, password_hash) 
		VALUES ($1, $2, $3, $4)`

	_, err := ar.db.Exec(query,
		user.ID,
		user.Username,
		user.Email,
		user.PasswordHash,
	)

	if err != nil {
		return fmt.Errorf("inserting user: %w", err)
	}

	return nil
}

func (ar *AuthRepository) GetUser(username string) (AuthUser, error) {
	query := `
		SELECT id, username, email, password_hash
		FROM users
		WHERE username = $1`

	var user AuthUser
	err := ar.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
	)

	if err != nil {
		return AuthUser{}, fmt.Errorf("getting user: %w", err)
	}

	return user, nil
}

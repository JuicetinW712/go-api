package auth

import "errors"

// Service level errors
var (
	ErrInternal           = errors.New("internal server error")
	ErrNotFound           = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrConflict           = errors.New("user already exists")
)

// Db level errors
var (
	errDbNotFound     = errors.New("user not found in database")
	errDbDuplicateKey = errors.New("user already exists in database")
)

package user

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	repo IUserRepository
}

func NewUserService(repo IUserRepository) *UserService {
	return &UserService{repo}
}

func (us *UserService) CreateUser(user User, password string) error {
	data := []byte(password)
	encryptedPassword, err := bcrypt.GenerateFromPassword(data, bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	err = us.repo.CreateUser(dbUser{
		ID:           uuid.New().String(),
		Username:     user.Username,
		Email:        user.Email,
		PasswordHash: string(encryptedPassword),
	})
	if err != nil {
		if errors.Is(err, errDbDuplicateKey) {
			return ErrConflict
		}
		return fmt.Errorf("creating user: %w", ErrInternal)
	}

	return nil
}

func (us *UserService) GetUser(username string) (User, error) {
	dbUser, err := us.repo.GetUser(username)
	if err != nil {
		if errors.Is(err, errDbNotFound) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("getting user: %w", ErrInternal)
	}

	return User{
		ID:       dbUser.ID,
		Username: dbUser.Username,
		Email:    dbUser.Email,
	}, nil
}

func (us *UserService) ValidatePassword(username string, password string) error {
	dbUser, err := us.repo.GetUser(username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("getting user: %w", err)
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(dbUser.PasswordHash),
		[]byte(password),
	)
	if err != nil {
		return ErrInvalidCredentials
	}

	return nil
}

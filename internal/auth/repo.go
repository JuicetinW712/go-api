package auth

type AuthRepository struct{}

func NewAuthRepository() *AuthRepository {
	return &AuthRepository{}
}

// TODO - implement
func (ar *AuthRepository) CreateUser(user AuthUser) error {
	return nil
}

// TODO - implement
func (ar *AuthRepository) GetUser(username string) (AuthUser, error) {
	return AuthUser{}, nil
}

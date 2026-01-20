package user

type UserRepository struct{}

func NewUserRepository() *UserRepository {
	return &UserRepository{}
}

// Implement IUserRepository methods for UserRepository
func (ur *UserRepository) CreateUser(user dbUser) error {
	// Implementation here
	return nil
}

func (ur *UserRepository) GetUser(username string) (dbUser, error) {
	// Implementation here
	return dbUser{}, nil
}

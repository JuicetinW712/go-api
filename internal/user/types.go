package user

type dbUser struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type IUserRepository interface {
	CreateUser(user dbUser) error
	GetUser(username string) (dbUser, error)
}

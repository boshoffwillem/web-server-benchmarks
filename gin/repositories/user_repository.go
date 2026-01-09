package repositories

import "gin-benchmark/models"

type UserRepository struct {
	users []*models.User
}

func NewUserRepository() *UserRepository {
	return &UserRepository{
		users: []*models.User{
			{Id: "1", Name: "Gianfranco", Email: "gianfranco@email.com", Password: "Test123!"},
			{Id: "2", Name: "Gianfranco2", Email: "gianfranco@email.com", Password: "Test123!"},
			{Id: "3", Name: "Gianfranco3", Email: "gianfranco@email.com", Password: "Test123!"},
			{Id: "4", Name: "Gianfranco4", Email: "gianfranco@email.com", Password: "Test123!"},
			{Id: "5", Name: "Gianfranco5", Email: "gianfranco@email.com", Password: "Test123!"},
		},
	}
}

func (r *UserRepository) GetAllUsers() []*models.User {
	return r.users
}

func (r *UserRepository) GetUserById(id string) *models.User {
	for _, user := range r.users {
		if user.Id == id {
			return user
		}
	}
	return nil
}

func (r *UserRepository) GetUserByEmail(email string) *models.User {
	for _, user := range r.users {
		if user.Email == email {
			return user
		}
	}
	return nil
}

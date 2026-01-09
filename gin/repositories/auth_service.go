package repositories

import (
	"gin-benchmark/models"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type AuthService struct {
	userRepository *UserRepository
}

func NewAuthService(userRepository *UserRepository) *AuthService {
	return &AuthService{userRepository: userRepository}
}

func (s *AuthService) FindByEmailAndPassword(email, password string) *models.User {
	user := s.userRepository.GetUserByEmail(email)
	if user != nil && user.Password == password {
		return user
	}
	return nil
}

func (s *AuthService) GenerateToken(user *models.User) (string, error) {
	key := []byte("8d96c0a4544eb9dad7c6b2f1126f52d272d0d04074edbf0cb92f3a68fb")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"nameidentifier": user.Id,
		"name":           user.Name,
		"email":          user.Email,
		"exp":            time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

package main

import (
	"gin-benchmark/handlers"
	"gin-benchmark/middleware"
	"gin-benchmark/repositories"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	// Initialize repositories
	userRepository := repositories.NewUserRepository()
	productRepository := repositories.NewProductRepository()
	categoryRepository := repositories.NewCategoryRepository()

	// Initialize services
	authService := repositories.NewAuthService(userRepository)

	// Register routes
	handlers.RegisterAuthRoutes(router, authService)
	handlers.RegisterUserRoutes(router, userRepository, middleware.AuthMiddleware())
	handlers.RegisterProductRoutes(router, productRepository, middleware.AuthMiddleware())
	handlers.RegisterCategoryRoutes(router, categoryRepository, middleware.AuthMiddleware())

	router.Run(":8080")
}

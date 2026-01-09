package handlers

import (
	"gin-benchmark/repositories"
	"github.com/gin-gonic/gin"
	"net/http"
)

func RegisterUserRoutes(router *gin.Engine, userRepository *repositories.UserRepository, authMiddleware gin.HandlerFunc) {
	users := router.Group("/api/v1/user")
	users.Use(authMiddleware)
	{
		users.GET("/:id", func(c *gin.Context) {
			id := c.Param("id")
			user := userRepository.GetUserById(id)

			if user == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"user": user})
		})
	}
}

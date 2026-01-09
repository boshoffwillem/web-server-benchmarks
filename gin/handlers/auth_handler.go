package handlers

import (
	"gin-benchmark/models"
	"gin-benchmark/repositories"
	"github.com/gin-gonic/gin"
	"net/http"
)

func RegisterAuthRoutes(router *gin.Engine, authService *repositories.AuthService) {
	auth := router.Group("/api/v1/auth")
	{
		auth.POST("/login", func(c *gin.Context) {
			var req models.LoginRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
				return
			}

			user := authService.FindByEmailAndPassword(req.Email, req.Password)
			if user == nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			token, err := authService.GenerateToken(user)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
				return
			}

			c.JSON(http.StatusOK, models.LoginResponse{Token: token})
		})
	}
}

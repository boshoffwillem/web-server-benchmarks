package handlers

import (
	"gin-benchmark/repositories"
	"github.com/gin-gonic/gin"
	"net/http"
)

func RegisterCategoryRoutes(router *gin.Engine, categoryRepository *repositories.CategoryRepository, authMiddleware gin.HandlerFunc) {
	categories := router.Group("/api/v1/category")
	categories.Use(authMiddleware)
	{
		categories.GET("/:id", func(c *gin.Context) {
			id := c.Param("id")
			category := categoryRepository.GetCategoryById(id)

			if category == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Category not found"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"category": category})
		})
	}
}

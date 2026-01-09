package handlers

import (
	"gin-benchmark/repositories"
	"github.com/gin-gonic/gin"
	"net/http"
)

func RegisterProductRoutes(router *gin.Engine, productRepository *repositories.ProductRepository, authMiddleware gin.HandlerFunc) {
	products := router.Group("/api/v1/product")
	products.Use(authMiddleware)
	{
		products.GET("", func(c *gin.Context) {
			allProducts := productRepository.GetAllProducts()
			c.JSON(http.StatusOK, gin.H{"products": allProducts})
		})

		products.GET("/:id", func(c *gin.Context) {
			id := c.Param("id")
			product := productRepository.GetProductById(id)

			if product == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"product": product})
		})
	}
}

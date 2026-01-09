package repositories

import (
	"fmt"
	"gin-benchmark/models"
)

type ProductRepository struct {
	products []*models.Product
}

func NewProductRepository() *ProductRepository {
	products := make([]*models.Product, 0, 10000)
	for i := 1; i <= 10000; i++ {
		userId := ((i % 5) + 1)
		categoryId := ((i % 5) + 1)
		products = append(products, &models.Product{
			Id:          fmt.Sprintf("%d", i),
			Name:        fmt.Sprintf("Product %d", i),
			Description: fmt.Sprintf("Description for product %d", i),
			UserId:      fmt.Sprintf("%d", userId),
			Price:       float64(i) * 1.5,
			CategoryId:  fmt.Sprintf("%d", categoryId),
		})
	}
	return &ProductRepository{products: products}
}

func (r *ProductRepository) GetAllProducts() []*models.Product {
	return r.products
}

func (r *ProductRepository) GetProductById(id string) *models.Product {
	for _, product := range r.products {
		if product.Id == id {
			return product
		}
	}
	return nil
}

package repositories

import "gin-benchmark/models"

type CategoryRepository struct {
	categories []*models.Category
}

func NewCategoryRepository() *CategoryRepository {
	return &CategoryRepository{
		categories: []*models.Category{
			{Id: "1", Name: "Dairy"},
			{Id: "2", Name: "Fruit"},
			{Id: "3", Name: "Vegetables"},
			{Id: "4", Name: "Bakery"},
			{Id: "5", Name: "Meat"},
		},
	}
}

func (r *CategoryRepository) GetAllCategories() []*models.Category {
	return r.categories
}

func (r *CategoryRepository) GetCategoryById(id string) *models.Category {
	for _, category := range r.categories {
		if category.Id == id {
			return category
		}
	}
	return nil
}

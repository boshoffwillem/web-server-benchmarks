package models

type Product struct {
	Id          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	UserId      string  `json:"userId"`
	Price       float64 `json:"price"`
	CategoryId  string  `json:"categoryId"`
}

use crate::models::{User, Product, Category};

#[derive(Clone)]
pub struct UserRepository {
    users: Vec<User>,
}

impl UserRepository {
    pub fn new() -> Self {
        UserRepository {
            users: vec![
                User {
                    id: "1".to_string(),
                    name: "Gianfranco".to_string(),
                    email: "gianfranco@email.com".to_string(),
                    password: "Test123!".to_string(),
                },
                User {
                    id: "2".to_string(),
                    name: "Gianfranco2".to_string(),
                    email: "gianfranco@email.com".to_string(),
                    password: "Test123!".to_string(),
                },
                User {
                    id: "3".to_string(),
                    name: "Gianfranco3".to_string(),
                    email: "gianfranco@email.com".to_string(),
                    password: "Test123!".to_string(),
                },
                User {
                    id: "4".to_string(),
                    name: "Gianfranco4".to_string(),
                    email: "gianfranco@email.com".to_string(),
                    password: "Test123!".to_string(),
                },
                User {
                    id: "5".to_string(),
                    name: "Gianfranco5".to_string(),
                    email: "gianfranco@email.com".to_string(),
                    password: "Test123!".to_string(),
                },
            ],
        }
    }

    pub fn get_all_users(&self) -> Vec<User> {
        self.users.clone()
    }

    pub fn get_user_by_id(&self, id: &str) -> Option<User> {
        self.users.iter().find(|u| u.id == id).cloned()
    }

    pub fn get_user_by_email(&self, email: &str) -> Option<User> {
        self.users.iter().find(|u| u.email == email).cloned()
    }
}

pub struct ProductRepository {
    products: Vec<Product>,
}

impl Clone for ProductRepository {
    fn clone(&self) -> Self {
        ProductRepository {
            products: self.products.clone(),
        }
    }
}

impl ProductRepository {
    pub fn new() -> Self {
        let mut products = Vec::new();
        for i in 1..=10000 {
            let user_id = ((i % 5) + 1).to_string();
            let category_id = ((i % 5) + 1).to_string();
            products.push(Product {
                id: i.to_string(),
                name: format!("Product {}", i),
                description: format!("Description for product {}", i),
                user_id,
                price: i as f64 * 1.5,
                category_id,
            });
        }
        ProductRepository { products }
    }

    pub fn get_all_products(&self) -> Vec<Product> {
        self.products.clone()
    }

    pub fn get_product_by_id(&self, id: &str) -> Option<Product> {
        self.products.iter().find(|p| p.id == id).cloned()
    }
}

pub struct CategoryRepository {
    categories: Vec<Category>,
}

impl Clone for CategoryRepository {
    fn clone(&self) -> Self {
        CategoryRepository {
            categories: self.categories.clone(),
        }
    }
}

impl CategoryRepository {
    pub fn new() -> Self {
        CategoryRepository {
            categories: vec![
                Category {
                    id: "1".to_string(),
                    name: "Dairy".to_string(),
                },
                Category {
                    id: "2".to_string(),
                    name: "Fruit".to_string(),
                },
                Category {
                    id: "3".to_string(),
                    name: "Vegetables".to_string(),
                },
                Category {
                    id: "4".to_string(),
                    name: "Bakery".to_string(),
                },
                Category {
                    id: "5".to_string(),
                    name: "Meat".to_string(),
                },
            ],
        }
    }

    pub fn get_all_categories(&self) -> Vec<Category> {
        self.categories.clone()
    }

    pub fn get_category_by_id(&self, id: &str) -> Option<Category> {
        self.categories.iter().find(|c| c.id == id).cloned()
    }
}

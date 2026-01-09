use actix_web::{web, HttpResponse};
use serde_json::json;
use crate::repositories::{UserRepository, ProductRepository, CategoryRepository};

pub async fn get_user(
    path: web::Path<String>,
    user_repo: web::Data<UserRepository>,
) -> HttpResponse {
    let id = path.into_inner();

    match user_repo.get_user_by_id(&id) {
        Some(user) => HttpResponse::Ok().json(json!({"user": user})),
        None => HttpResponse::NotFound().json(json!({"error": "User not found"})),
    }
}

pub async fn get_all_products(
    product_repo: web::Data<ProductRepository>,
) -> HttpResponse {
    let products = product_repo.get_all_products();
    HttpResponse::Ok().json(json!({"products": products}))
}

pub async fn get_product(
    path: web::Path<String>,
    product_repo: web::Data<ProductRepository>,
) -> HttpResponse {
    let id = path.into_inner();

    match product_repo.get_product_by_id(&id) {
        Some(product) => HttpResponse::Ok().json(json!({"product": product})),
        None => HttpResponse::NotFound().json(json!({"error": "Product not found"})),
    }
}

pub async fn get_category(
    path: web::Path<String>,
    category_repo: web::Data<CategoryRepository>,
) -> HttpResponse {
    let id = path.into_inner();

    match category_repo.get_category_by_id(&id) {
        Some(category) => HttpResponse::Ok().json(json!({"category": category})),
        None => HttpResponse::NotFound().json(json!({"error": "Category not found"})),
    }
}

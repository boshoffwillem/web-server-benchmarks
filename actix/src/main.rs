mod models;
mod repositories;
mod auth;
mod middleware;
mod handlers;
mod routes;

use actix_web::{web, App, HttpServer};
use repositories::{UserRepository, ProductRepository, CategoryRepository};
use auth::AuthService;
use handlers::login;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let user_repo = UserRepository::new();
    let product_repo = web::Data::new(ProductRepository::new());
    let category_repo = web::Data::new(CategoryRepository::new());
    let auth_service = web::Data::new(AuthService::new(user_repo.clone()));
    let user_repo = web::Data::new(user_repo);

    println!("Server running on http://localhost:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(user_repo.clone())
            .app_data(product_repo.clone())
            .app_data(category_repo.clone())
            .app_data(auth_service.clone())
            .route("/api/v1/auth/login", web::post().to(login))
            .service(
                web::scope("/api/v1")
                    .wrap(middleware::AuthMiddleware)
                    .route("/user/{id}", web::get().to(routes::get_user))
                    .route("/product", web::get().to(routes::get_all_products))
                    .route("/product/{id}", web::get().to(routes::get_product))
                    .route("/category/{id}", web::get().to(routes::get_category))
            )
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

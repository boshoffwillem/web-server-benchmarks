use actix_web::{web, HttpResponse, Responder};
use serde_json::json;
use crate::models::{LoginRequest, LoginResponse};
use crate::auth::AuthService;
use crate::repositories::UserRepository;

pub async fn login(
    req: web::Json<LoginRequest>,
    _user_repo: web::Data<UserRepository>,
    auth_service: web::Data<AuthService>,
) -> impl Responder {
    let user = auth_service.find_by_email_and_password(&req.email, &req.password);

    match user {
        Some(user) => {
            match auth_service.generate_token(&user) {
                Ok(token) => HttpResponse::Ok().json(LoginResponse { token }),
                Err(_) => HttpResponse::InternalServerError().json(json!({"error": "Failed to generate token"})),
            }
        }
        None => HttpResponse::Unauthorized().json(json!({"error": "Unauthorized"})),
    }
}

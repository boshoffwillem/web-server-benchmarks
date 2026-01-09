use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures::future::LocalBoxFuture;
use std::future::{ready, Ready};
use crate::auth::AuthService;

pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService { service }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth_header = req.headers().get("Authorization");

        match auth_header {
            Some(header) => {
                let header_str = match header.to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        return Box::pin(async move {
                            Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
                        });
                    }
                };

                let parts: Vec<&str> = header_str.split_whitespace().collect();
                if parts.len() != 2 || parts[0] != "Bearer" {
                    return Box::pin(async move {
                        Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
                    });
                }

                let token = parts[1].to_string();
                if AuthService::verify_token(&token).is_err() {
                    return Box::pin(async move {
                        Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
                    });
                }

                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res)
                })
            }
            None => {
                return Box::pin(async move {
                    Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
                });
            }
        }
    }
}

use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::repositories::UserRepository;

const SECRET: &[u8] = b"8d96c0a4544eb9dad7c6b2f1126f52d272d0d04074edbf0cb92f3a68fb";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub nameidentifier: String,
    pub name: String,
    pub email: String,
    pub exp: usize,
}

#[derive(Clone)]
pub struct AuthService {
    user_repository: UserRepository,
}

impl AuthService {
    pub fn new(user_repository: UserRepository) -> Self {
        AuthService { user_repository }
    }

    pub fn find_by_email_and_password(&self, email: &str, password: &str) -> Option<User> {
        if let Some(user) = self.user_repository.get_user_by_email(email) {
            if user.password == password {
                return Some(user);
            }
        }
        None
    }

    pub fn generate_token(&self, user: &User) -> Result<String, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let claims = Claims {
            nameidentifier: user.id.clone(),
            name: user.name.clone(),
            email: user.email.clone(),
            exp: (now + 86400) as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .map_err(|e| e.to_string())
    }

    pub fn verify_token(token: &str) -> Result<Claims, String> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(SECRET),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|e| e.to_string())
    }
}

use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        tracing::error!("Error occurred: {}", self);

        match self {
            AppError::Unauthorized(_) => {
                HttpResponse::Unauthorized().json(serde_json::json!({"error": self.to_string()}))
            }
            AppError::BadRequest(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({"error": self.to_string()}))
            }
            _ => HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Internal server error"})),
        }
    }
}

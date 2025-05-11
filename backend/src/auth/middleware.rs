use actix_web::{FromRequest, HttpRequest, dev::Payload, http::header};
use futures::future::{Ready, ready};
use jsonwebtoken::{DecodingKey, Validation, decode};
use std::env;
use tracing::{error, info, warn};

use super::Claims;
use crate::errors::AppError;

impl FromRequest for Claims {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let auth_header = match req.headers().get(header::AUTHORIZATION) {
            Some(header) => header,
            None => {
                warn!("Missing Authorization header");
                return ready(Err(AppError::Unauthorized(
                    "Missing Authorization header".to_string(),
                )));
            }
        };

        let auth_str = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => {
                warn!("Invalid Authorization header format");
                return ready(Err(AppError::Unauthorized(
                    "Invalid Authorization header format.".to_string(),
                )));
            }
        };

        if !auth_str.starts_with("Bearer") {
            warn!("Invalid Authorization header: missing Bearer");
            return ready(Err(AppError::Unauthorized(
                "Invalid Authoriaztion header: missing Bearer".to_string(),
            )));
        }

        let token = auth_str.trim_start_matches("Bearer ");
        let jwt_secret = match env::var("JWT_SECRET") {
            Ok(secret) => secret,
            Err(_) => {
                error!("JWT_SECRET not set");
                return ready(Err(AppError::Internal(
                    "Server configuration error".to_string(),
                )));
            }
        };

        match decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_ref()),
            &Validation::default(),
        ) {
            Ok(token_data) => {
                info!(
                    "Successfully validated token for user: {}",
                    token_data.claims.sub
                );
                ready(Ok(token_data.claims))
            }
            Err(e) => {
                warn!("Failed to validate token: {}", e);
                ready(Err(AppError::Unauthorized("Invalid token".to_string())))
            }
        }
    }
}

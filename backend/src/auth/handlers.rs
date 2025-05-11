use actix_web::{HttpResponse, web};
use bcrypt::verify;
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use sqlx::PgPool;
use std::env;
use tracing::{error, info};
use uuid::Uuid;

use super::{Claims, LoginRequest, LoginResponse, RegisterRequest};
use crate::errors::AppError;

pub async fn register(
    pool: web::Data<PgPool>,
    user: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    info!("Registering new user: {}", user.email);

    let password_hash = bcrypt::hash(&user.password, bcrypt::DEFAULT_COST)?;
    let user_id = sqlx::query!(
        r#"
            INSERT INTO users (id, username, email, password_hash)
            VALUES ($1, $2, $3, $4)
            RETURNING id
        "#,
        Uuid::new_v4(),
        user.username,
        user.email,
        password_hash
    )
    .fetch_one(pool.get_ref())
    .await
    .map(|rec| rec.id)?;

    info!("User registered successfully: {}", user_id);

    Ok(HttpResponse::Created().json(serde_json::json!({
        "message": "User registered successfully",
        "user_id": user_id
    })))
}

pub async fn login(
    pool: web::Data<PgPool>,
    login: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    info!("Login attempt for: {}", login.email);

    let user = sqlx::query_as::<_, super::User>("SELECT * FROM users WHERE email = $1 LIMIT 1")
        .bind(&login.email)
        .fetch_optional(pool.get_ref())
        .await?;

    let user = user.ok_or_else(|| {
        let err = AppError::Unauthorized("Invalid credentials".to_string());
        error!("{}", err);
        err
    })?;

    if !verify(&login.password, &user.password_hash)? {
        let err = AppError::Unauthorized("Invalid credentials".to_string());
        error!("{}", err);
        return Err(err);
    }

    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;
    let claims = Claims {
        sub: user.id.to_string(),
        exp: expiration,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )?;

    info!("User logged in successfully: {}", user.id);

    Ok(HttpResponse::Ok().json(LoginResponse { token }))
}

pub async fn protected(claims: web::ReqData<Claims>) -> Result<HttpResponse, AppError> {
    info!("Accessing protected route for user: {}", claims.sub);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "This is a protected route",
        "user_id": claims.sub
    })))
}

use actix_cors::Cors;
use actix_web::{App, HttpServer, http, middleware, web};
use dotenv::dotenv;
use tracing::info;
use tracing_subscriber;

mod auth;
mod db;
mod errors;

use auth::{login, protected, register};
use db::init_db_pool;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting application");

    let pool = init_db_pool()
        .await
        .expect("Failed to initialize database pool");
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a number");
    info!("Server starting on port {}", port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST", "PATCH"])
            .allowed_headers(vec![
                http::header::CONTENT_TYPE,
                http::header::AUTHORIZATION,
            ]);

        App::new()
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(
                web::scope("/api")
                    .route("/register", web::post().to(register))
                    .route("/login", web::post().to(login))
                    .route("/protected", web::get().to(protected)),
            )
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}

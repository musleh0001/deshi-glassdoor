use dotenv::dotenv;
use sqlx::{Pool, Postgres};
use std::env;
use tracing::info;

pub async fn init_db_pool() -> Result<Pool<Postgres>, sqlx::Error> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    info!("Initializing database connection pool");
    let pool = Pool::connect(&database_url).await?;
    info!("Running database migrations");
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}

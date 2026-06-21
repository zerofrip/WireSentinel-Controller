use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::ConnectOptions;
use std::str::FromStr;
use std::time::Duration;

pub mod models;

pub type DbPool = SqlitePool;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("not found: {0}")]
    NotFound(String),
}

pub async fn connect(database_url: &str) -> Result<DbPool, DbError> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .foreign_keys(true)
        .disable_statement_logging();

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;

    Ok(pool)
}

pub async fn migrate(pool: &DbPool) -> Result<(), DbError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| DbError::Sqlx(sqlx::Error::Migrate(Box::new(e))))?;
    Ok(())
}

pub async fn setup(database_url: &str) -> Result<DbPool, DbError> {
    let pool = connect(database_url).await?;
    migrate(&pool).await?;
    Ok(pool)
}

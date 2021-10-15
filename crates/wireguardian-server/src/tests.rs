//! Common Shared Test Functions

use crate::models::{TotpParams, User};
use color_eyre::eyre;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;

#[derive(Debug)]
pub struct TestUser {
    pub username: String,
    pub email: String,
    pub password: String,
    pub totp: TotpParams,
}

/// Creates a new in-memory sqlite database
pub async fn setup() -> eyre::Result<(SqlitePool, Vec<TestUser>)> {
    // connect to the backing sqlite database
    let options = SqliteConnectOptions::from_str("sqlite::memory:")?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);

    let pool = SqlitePoolOptions::new()
        .min_connections(1)
        .max_connections(1)
        .connect_with(options)
        .await?;

    // run any pending migraionts
    sqlx::migrate!().run(&pool).await?;

    let users = vec![
        TestUser {
            username: "user1".into(),
            email: "user1@example.com".into(),
            password: "hunter42".into(),
            totp: TotpParams::generate(),
        },
        TestUser {
            username: "user2".into(),
            email: "user2@example.com".into(),
            password: "hunter43".into(),
            totp: TotpParams::generate(),
        },
    ];

    for user in &users {
        User::create(
            &pool,
            user.username.clone(),
            user.email.clone(),
            user.password.clone(),
            user.totp.clone(),
        )
        .await?;
    }

    Ok((pool, users))
}

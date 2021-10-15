//! Represents a User

use crate::models::TotpParams;
use color_eyre::eyre;
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    /// Universally Unique Identifier (UUID)
    id: String,

    /// Unique username belonging to this user
    pub username: String,

    /// Unique email belonging to this user
    pub email: String,
}

impl User {
    /// Creates a new user and saves them in the database
    ///
    /// # Arguments
    /// * `db` - Connection to backend database
    /// * `username`- Unique username for user
    /// * `email` - Unique email for user
    /// * `password` - Password for user
    /// * `totp_key` - TOTP unique secret key
    pub async fn create(
        db: &SqlitePool,
        username: String,
        email: String,
        password: String,
        totp_params: TotpParams,
    ) -> eyre::Result<Self> {
        let id = Uuid::new_v4().to_hyphenated().to_string();
        let user = User {
            id,
            username,
            email,
        };

        sqlx::query!(
            "INSERT INTO users (id, username, email) VALUES (?, ?, ?)",
            user.id,
            user.username,
            user.email
        )
        .execute(db)
        .await?;

        sqlx::query!(
            "INSERT INTO passwords (user_id, password) VALUES (?, ?)",
            user.id,
            password
        )
        .execute(db)
        .await?;

        totp_params.save(db, &user).await?;

        Ok(user)
    }

    /// Attempts to fetch a user from the backend with the specified email address
    ///
    /// # Arguments
    /// * `db` - Connection to backend database
    /// * `email` - Email of user to fetch
    ///
    /// # Errors
    /// If the backend isn't initialize
    /// If the email doesn't have a corresponding user
    pub async fn fetch_by_email(db: &SqlitePool, email: &str) -> eyre::Result<Self> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, username, email FROM users WHERE email = ?",
            email
        )
        .fetch_one(db)
        .await?;

        Ok(user)
    }

    /// Returns the unique identifier representing this user
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Attempts to fetch a user from the backend with the specified email address and validate the
    /// user's password and totp code against the supplied values
    ///
    /// # Arguments
    /// * `email` - Email of user to fetch
    /// * `password` - Password provided by the remote user
    /// * `totp` - TOTP code provided by the remote user
    ///
    /// # Errors
    /// If the backend isn't initialize
    /// If the email doesn't have a corresponding user
    pub async fn fetch_and_validate(
        db: &SqlitePool,
        email: &str,
        password: &str,
        totp: u32,
    ) -> eyre::Result<Self> {
        let user = Self::fetch_by_email(db, email).await?;
        user.validate_password(db, password).await?;
        user.validate_totp(db, totp).await?;
        Ok(user)
    }

    /// Validates a password against the value stored in the database.  Returns true if the
    /// password matches what is stored in the database, returns false otherwise
    ///
    /// # Arguments
    /// * `db` - Connection to backend database
    /// * `pw` - Password received from the user to validate
    pub async fn validate_password(&self, db: &SqlitePool, pw: &str) -> eyre::Result<()> {
        #[derive(Debug, sqlx::FromRow)]
        struct Password {
            password: String,
        }

        let user_id = &self.id;
        let stored = sqlx::query_as!(
            Password,
            "SELECT password FROM passwords WHERE user_id = ?",
            user_id
        )
        .fetch_one(db)
        .await?;

        // TODO actually implement password hashing...
        if stored.password == pw {
            Ok(())
        } else {
            eyre::bail!("invalid password")
        }
    }

    /// Validates a password against the value stored in the database.  Returns true if the
    /// password matches what is stored in the database, returns false otherwise
    ///
    /// # Arguments
    /// * `db` - Connection to backend database
    /// * `totp` - TOTP value to validate
    pub async fn validate_totp(&self, db: &SqlitePool, totp: u32) -> eyre::Result<()> {
        let params = TotpParams::fetch_by_user(db, self).await?;
        params.validate(totp)?;
        Ok(())
    }
}

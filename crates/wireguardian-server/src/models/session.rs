//! Sessions Database Model

use crate::models::User;
use chrono::NaiveDateTime;
use color_eyre::eyre;
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub struct Session {
    // UUID / Strong Random session identifier
    id: String,

    // User id of session owner (user)
    user_id: String,

    // flag to check for expiration
    expired: bool,

    // date/time this session was created (in UTC)
    created: NaiveDateTime,

    // date/time this session was last modified (in UTC)
    modified: NaiveDateTime,
}

impl Session {
    /// Creates a new session linked to a `User`
    ///
    /// # Arguments
    /// * `db` - Connection to the backend session storage service
    /// * `user` - User who will own the session
    ///
    /// # Errors
    /// * If the backend session store conenction fails
    pub async fn create(db: &SqlitePool, user: &User) -> eyre::Result<Self> {
        let id = Uuid::new_v4().to_hyphenated();
        {
            let id = &id;
            let user_id = user.id();

            sqlx::query!(
                "INSERT INTO sessions (id, user_id, expired) VALUES (?, ?, ?)",
                id,
                user_id,
                false
            )
            .execute(db)
            .await?;
        }

        Self::fetch(db, &id.to_string()).await
    }

    /// Fetches an active (non-expired) session by id from the session storage service
    ///
    /// # Arguments
    /// * `db` - Connection to the backend session storage service
    /// * `id` - Unique id of the session
    pub async fn fetch(db: &SqlitePool, id: &str) -> eyre::Result<Self> {
        let session = sqlx::query_as!(
            Session,
            "SELECT id, user_id, expired, created, modified FROM sessions WHERE id = ?",
            id,
        )
        .fetch_one(db)
        .await?;

        if session.is_expired() {
            eyre::bail!("session is expired")
        } else {
            Ok(session)
        }
    }

    /// Marks this session as expired in the backend
    ///
    /// # Arguments
    /// * `db` - Connection to the backend session storage service
    ///
    /// # Errors
    /// * If the backend session store conenction fails
    pub async fn expire(self, db: &SqlitePool) -> eyre::Result<()> {
        sqlx::query!("UPDATE sessions SET expired = true WHERE id = ?", self.id)
            .execute(db)
            .await?;
        Ok(())
    }

    /// Returns the unique identifier for this session
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Returns true if this session is expired
    pub fn is_expired(&self) -> bool {
        self.expired
    }
}

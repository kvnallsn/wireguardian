//! Sessions Database Model

use crate::models::User;
use chrono::NaiveDateTime;
use color_eyre::eyre;
use sqlx::sqlite::SqlitePool;
use std::{convert::TryInto, net::Ipv4Addr};
use uuid::Uuid;

macro_rules! parse_session_row {
    ($row:expr) => {{
        let id: [u8; 16] = $row
            .id
            .try_into()
            .map_err(|_| eyre::eyre!("uuid must be 16 bytes"))?;
        let user_id: [u8; 16] = $row
            .user_id
            .try_into()
            .map_err(|_| eyre::eyre!("uuid must be 16 bytes"))?;
        let ip: u32 = $row.ip.try_into()?;
        Session {
            id: Uuid::from_bytes(id),
            user_id: Uuid::from_bytes(user_id),
            ip: Ipv4Addr::from(ip),
            expired: $row.expired,
            created: $row.created,
            modified: $row.modified,
        }
    }};
}

#[derive(Debug)]
pub struct Session {
    /// UUID / Strong Random session identifier
    id: Uuid,

    /// User id of session owner (user)
    user_id: Uuid,

    /// IPv4 address assigned to this session
    ip: Ipv4Addr,

    /// flag to check for expiration
    expired: bool,

    /// date/time this session was created (in UTC)
    created: NaiveDateTime,

    /// date/time this session was last modified (in UTC)
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
    pub async fn create(db: &SqlitePool, user: &User, ip: Ipv4Addr) -> eyre::Result<Self> {
        let id = Uuid::new_v4();
        {
            let user_id = user.id();
            let ip: u32 = ip.into();

            sqlx::query!(
                "INSERT INTO sessions (id, user_id, ip, expired) VALUES (?, ?, ?, ?)",
                id,
                user_id,
                ip,
                false
            )
            .execute(db)
            .await?;
        }

        Self::fetch(db, id).await
    }

    /// Fetches an active (non-expired) session by id from the session storage service
    ///
    /// # Arguments
    /// * `db` - Connection to the backend session storage service
    /// * `id` - Unique id of the session
    pub async fn fetch(db: &SqlitePool, id: Uuid) -> eyre::Result<Self> {
        let row = sqlx::query!(
            "SELECT id, user_id, ip, expired, created, modified FROM sessions WHERE id = ?",
            id,
        )
        .fetch_one(db)
        .await?;

        let session = parse_session_row!(row);

        if session.is_expired() {
            eyre::bail!("session is expired")
        } else {
            Ok(session)
        }
    }

    /// Fetches all active, non-expired sessions from the database
    ///
    /// # Arguments
    /// * `db` - Connection to the backend session storage service
    pub async fn fetch_all(db: &SqlitePool) -> eyre::Result<Vec<Self>> {
        let rows = sqlx::query!(
            "SELECT id, user_id, ip, expired, created, modified FROM sessions WHERE expired = false"
        )
        .fetch_all(db)
        .await?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(parse_session_row!(row));
        }
        Ok(sessions)
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
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the unique identifier for this session as a string
    pub fn id_str(&self) -> String {
        self.id.to_hyphenated().to_string()
    }

    /// Returns true if this session is expired
    pub fn is_expired(&self) -> bool {
        self.expired
    }

    /// Returns the ip assigned to this session
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }
}

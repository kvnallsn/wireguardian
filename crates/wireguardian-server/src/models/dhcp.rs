//! DHCP

use crate::models::Session;
use chrono::NaiveDateTime;
use color_eyre::eyre;
use sqlx::sqlite::SqlitePool;
use std::{convert::TryInto, net::Ipv4Addr};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub struct Dhcp {
    /// UUID / Strong Random session identifier
    pub id: Uuid,

    /// User id of session owner (user)
    pub session_id: String,

    /// IPv4 address that was assigned for this session
    pub ip: Ipv4Addr,

    /// flag to check if lease is active
    pub active: bool,

    /// date/time this session was created (in UTC)
    pub created: NaiveDateTime,

    /// date/time this session was last modified (in UTC)
    pub released: Option<NaiveDateTime>,
}

impl Dhcp {
    /// Creates a new DHCP lease linked to a user
    ///
    /// # Arguments
    /// * `db` - Connection to the backend session storage service
    /// * `id` - Unique id to represent this lease
    /// * `session` - Session that will own the dhcp lease
    /// * `ip` - IPv4 address to lease
    ///
    /// # Errors
    /// * If the backend dhcp lease store conenction fails
    pub async fn create(
        db: &SqlitePool,
        id: Uuid,
        session: &Session,
        ip: Ipv4Addr,
    ) -> eyre::Result<Self> {
        {
            let id = id.to_hyphenated();
            let session_id = session.id();
            let ip: u32 = ip.into();

            sqlx::query!(
                "INSERT INTO dhcp (id, session_id, ip, active) VALUES (?, ?, ?, ?)",
                id,
                session_id,
                ip,
                true,
            )
            .execute(db)
            .await?;
        }

        Self::fetch(db, id).await
    }

    /// Fetches a DHCP lease by id from the dhcp lease service
    ///
    /// # Arguments
    /// * `db` - Connection to the backend dhcp service
    /// * `id` - Unique id of the lease
    pub async fn fetch(db: &SqlitePool, id: Uuid) -> eyre::Result<Self> {
        let id = id.to_hyphenated();
        let dhcp = sqlx::query!(
            "SELECT id, session_id, ip, active, created, released FROM dhcp WHERE id = ?",
            id,
        )
        .fetch_one(db)
        .await?;

        let ip: u32 = dhcp.ip.try_into()?;

        Ok(Self {
            id: dhcp.id.parse()?,
            session_id: dhcp.session_id,
            ip: ip.into(),
            active: dhcp.active,
            created: dhcp.created,
            released: dhcp.released,
        })
    }

    /// Fetches all DHCP leases for a session
    ///
    /// # Arguments
    /// * `db` - Connection to the backend dhcp service
    /// * `id` - Unique id of the lease
    pub async fn fetch_by_session_id(db: &SqlitePool, id: Uuid) -> eyre::Result<Vec<Self>> {
        let id = id.to_hyphenated();
        let leases = sqlx::query!(
            "SELECT id, session_id, ip, active, created, released FROM dhcp WHERE session_id = ?",
            id,
        )
        .fetch_all(db)
        .await?;

        let mut leased = Vec::new();
        for lease in leases {
            let ip: u32 = lease.ip.try_into()?;

            leased.push(Self {
                id: lease.id.parse()?,
                session_id: lease.session_id,
                ip: ip.into(),
                active: lease.active,
                created: lease.created,
                released: lease.released,
            });
        }

        Ok(leased)
    }

    /// Fetches all leased ips from the dhcp lease service
    ///
    /// # Arguments
    /// * `db` - Connection to the backend dhcp service
    pub async fn fetch_leased(db: &SqlitePool) -> eyre::Result<Vec<Self>> {
        let leases = sqlx::query!(
            "SELECT id, session_id, ip, active, created, released FROM dhcp WHERE active = true",
        )
        .fetch_all(db)
        .await?;

        let mut leased = Vec::new();
        for lease in leases {
            let ip: u32 = lease.ip.try_into()?;

            leased.push(Self {
                id: lease.id.parse()?,
                session_id: lease.session_id,
                ip: ip.into(),
                active: lease.active,
                created: lease.created,
                released: lease.released,
            });
        }

        Ok(leased)
    }

    /// Marks this lease as released in the backend
    ///
    /// # Arguments
    /// * `db` - Connection to the backend service
    ///
    /// # Errors
    /// * If the backend conenction fails
    pub async fn release(self, db: &SqlitePool) -> eyre::Result<()> {
        let id = self.id.to_hyphenated();
        sqlx::query!("UPDATE dhcp SET active = false  WHERE id = ?", id)
            .execute(db)
            .await?;
        Ok(())
    }

    /// Returns true if this lease is currently active/leased
    pub fn is_active(&self) -> bool {
        self.active
    }
}

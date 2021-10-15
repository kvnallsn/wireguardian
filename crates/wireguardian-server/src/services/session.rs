//! Issues and tracks dynamic clients

use crate::{
    config::DhcpConfig,
    models::{Session, User},
};
use color_eyre::eyre::{self, WrapErr};
use parking_lot::RwLock;
use sqlx::sqlite::SqlitePool;
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};
use uuid::Uuid;

/// Responsible for tracking Internet Profocol (IP) addresses issued to clients after connecting
#[derive(Clone)]
pub struct SessionService {
    db: SqlitePool,

    dhcp: Arc<RwLock<HashMap<u32, Option<Uuid>>>>,
}

impl SessionService {
    /// Creates a new `DhcpService` that issues IPs between the start and end addresses
    ///
    /// # Arguments
    /// * `db` - Backend dhcp storage service
    /// * `cfg` - DHCP Server configuration options
    ///
    /// # Errors
    /// * If the end ip address is before the start address
    pub async fn new(db: SqlitePool, cfg: DhcpConfig) -> eyre::Result<Self> {
        // 1. validate config options
        if cfg.end < cfg.start {
            eyre::bail!(
                "end address ({}) must be after start address ({})",
                cfg.end,
                cfg.start
            );
        }

        // 2. populate initial database as all ips available
        let start: u32 = cfg.start.into();
        let end: u32 = cfg.end.into();
        let mut available: HashMap<u32, Option<Uuid>> =
            (start..end).into_iter().map(|ip| (ip, None)).collect();

        // 3. fetch all active sessions
        let sessions = Session::fetch_all(&db).await?;
        for session in sessions {
            available.insert(session.ip().into(), Some(session.id()));
        }

        Ok(Self {
            db,
            dhcp: Arc::new(RwLock::new(available)),
        })
    }

    /// Logs a user in and creates a new session for them
    ///
    /// # Arguments
    /// * `email` - Email of user to login
    /// * `password` - Password of use to login
    /// * `totp` - Time-Based One Time Password of user
    pub async fn login(
        &self,
        email: impl AsRef<str>,
        password: impl AsRef<str>,
        totp: u32,
    ) -> eyre::Result<Session> {
        // 1. validate user creeentials
        let user = User::fetch_and_validate(&self.db, email.as_ref(), password.as_ref(), totp)
            .await
            .wrap_err("failed to fetch and validate user")?;

        // 2. assign an ip address
        let ip: Ipv4Addr = {
            // Note: this exists in a smaller scope to avoid potentially sending the RwLock
            // (available) across threads (which the compilier will complain about).  When this
            // scope ends, the lock is dropped and the db update can continue asynchronously

            // 3. lock in-memory db to avoid race conditions
            let mut available = self.dhcp.write();

            // 4. find an available ip address
            let ip = match available
                .iter()
                .filter_map(|(&ip, &leased)| if leased.is_none() { Some(ip) } else { None })
                .next()
            {
                Some(ip) => ip,
                None => {
                    tracing::warn!("no more ips available for lease");
                    eyre::bail!("no more ips available for lease");
                }
            };

            // 5. mark ip as leased
            available.insert(ip, Some(Uuid::new_v4()));

            // 6. return the newly leased IP
            ip.into()
        };

        // 3. create the session
        let session = Session::create(&self.db, &user, ip)
            .await
            .wrap_err("failed to create session")?;

        Ok(session)
    }

    /// Attempts to fetch an active session with the corresponding unique id
    ///
    /// # Arguments
    /// * `token` - Session unique id / token
    pub async fn get(&self, token: impl AsRef<str>) -> eyre::Result<Session> {
        let token = token.as_ref();
        let session = Session::fetch(&self.db, token.parse()?).await?;
        Ok(session)
    }

    /// Releases an IP address back to the pool of available addresses
    ///
    /// # Arguments
    /// * `token` - Session Unique Id / Token
    pub async fn logout(&self, token: impl AsRef<str>) -> eyre::Result<()> {
        let session = self.get(token).await?;

        // 1. release the ip from the dhcp table
        {
            // Note: this exists in a smaller scope to avoid potentially sending the RwLock
            // (available) across threads (which the compilier will complain about).  When this
            // scope ends, the lock is dropped and the db update can continue asynchronously
            //
            // 2. lock in-memory db to avoid race conditions
            let mut available = self.dhcp.write();

            // 3. get lease id
            let ip: u32 = session.ip().into();

            // 4. mark ip as released
            available.insert(ip, None);
        }

        // 2. expure the session
        session.expire(&self.db).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DhcpConfig;
    use color_eyre::eyre;
    use sqlx::sqlite::SqlitePool;

    async fn create_session_service(db: SqlitePool) -> eyre::Result<SessionService> {
        Ok(SessionService::new(
            db,
            DhcpConfig {
                start: [192, 168, 0, 100].into(),
                end: [192, 168, 0, 105].into(),
            },
        )
        .await?)
    }

    #[tokio::test]
    async fn single_user() -> eyre::Result<()> {
        let (db, users) = crate::tests::setup().await?;
        let sessions = create_session_service(db.clone()).await?;

        // 1. login user and create session
        let session = sessions
            .login(&users[0].email, &users[0].password, users[0].totp.code()?)
            .await?;

        // 2. close session
        sessions.logout(session.id_str()).await?;

        Ok(())
    }

    #[tokio::test]
    async fn multi_user() -> eyre::Result<()> {
        let (db, users) = crate::tests::setup().await?;
        let sessions = create_session_service(db.clone()).await?;

        // 1. login user and create session
        let u0_session = sessions
            .login(&users[0].email, &users[0].password, users[0].totp.code()?)
            .await?;
        let u1_session = sessions
            .login(&users[1].email, &users[1].password, users[1].totp.code()?)
            .await?;

        // 2. ask for dhcp lease
        assert!(
            u0_session.ip() != u1_session.ip(),
            "user ip's should not match"
        );

        // 3. close sessions
        sessions.logout(u0_session.id_str()).await?;
        sessions.logout(u1_session.id_str()).await?;

        Ok(())
    }
}

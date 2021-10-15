//! Issues and tracks dynamic clients

use crate::{
    config::DhcpConfig,
    models::{Dhcp, Session},
};
use color_eyre::eyre;
use parking_lot::RwLock;
use sqlx::sqlite::SqlitePool;
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};
use uuid::Uuid;

/// Responsible for tracking Internet Profocol (IP) addresses issued to clients after connecting
#[derive(Clone)]
pub struct DhcpService(Arc<RwLock<HashMap<u32, Option<Uuid>>>>, SqlitePool);

impl DhcpService {
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

        // 3. fetch all leased ips from the database
        let leased = Dhcp::fetch_leased(&db).await?;
        for lease in leased {
            available.insert(lease.ip.into(), Some(lease.id));
        }

        Ok(Self(Arc::new(RwLock::new(available)), db))
    }

    /// Leases the next available IP address or `None` if no more IPs are available
    ///
    /// # Arguments
    /// * `session` - Session to associate with this lease
    pub async fn lease(&self, session: &Session) -> eyre::Result<Ipv4Addr> {
        // 1. generate a new lease id
        let id = Uuid::new_v4();

        // 2. check is session already has a lease
        let session_lease_count = Dhcp::fetch_by_session_id(&self.1, session.id().parse()?)
            .await?
            .into_iter()
            .filter(|lease| lease.is_active())
            .count();

        if session_lease_count > 0 {
            eyre::bail!("session already has a lease");
        }

        let ip = {
            // Note: this exists in a smaller scope to avoid potentially sending the RwLock
            // (available) across threads (which the compilier will complain about).  When this
            // scope ends, the lock is dropped and the db update can continue asynchronously

            // 3. lock in-memory db to avoid race conditions
            let mut available = self.0.write();

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
            available.insert(ip, Some(id));

            // 6. return the newly leased IP
            ip
        };

        // 7. persist this lease in the db
        Dhcp::create(&self.1, id, session, ip.into()).await?;

        Ok(ip.into())
    }

    /// Releases an IP address back to the pool of available addresses
    ///
    /// # Arguments
    /// * `session` - Session containing IP to release
    pub async fn release(&self, session: &Session) -> eyre::Result<()> {
        // 1. fetch the leases associated with this session
        let leases = Dhcp::fetch_by_session_id(&self.1, session.id().parse()?).await?;

        for lease in leases.into_iter().filter(|lease| lease.is_active()) {
            {
                // Note: this exists in a smaller scope to avoid potentially sending the RwLock
                // (available) across threads (which the compilier will complain about).  When this
                // scope ends, the lock is dropped and the db update can continue asynchronously
                //
                // 2. lock in-memory db to avoid race conditions
                let mut available = self.0.write();

                // 3. get lease id
                let ip: u32 = lease.ip.into();

                // 4. mark ip as released
                available.insert(ip, None);
            }

            // 4. mark as released in db
            lease.release(&self.1).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::DhcpConfig,
        models::{Session, User},
    };
    use color_eyre::eyre;
    use sqlx::sqlite::SqlitePool;
    use std::time::Duration;

    async fn create_dhcp_service(db: SqlitePool) -> eyre::Result<DhcpService> {
        Ok(DhcpService::new(
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
        let dhcp = create_dhcp_service(db.clone()).await?;

        // 1. login user and create session
        let user = User::fetch_and_validate(
            &db,
            &users[0].email,
            &users[0].password,
            users[0].totp.code()?,
        )
        .await?;
        let session = Session::create(&db, &user).await?;

        // 2. ask for dhcp lease
        let _ip = dhcp.lease(&session).await?;

        // 3. sleep for 1 second
        tokio::time::sleep(Duration::from_secs(1)).await;

        // 4. release dhcp lease
        dhcp.release(&session).await?;

        // 5. close session
        session.expire(&db).await?;

        Ok(())
    }

    #[tokio::test]
    async fn single_user_multi_lease() -> eyre::Result<()> {
        let (db, users) = crate::tests::setup().await?;
        let dhcp = create_dhcp_service(db.clone()).await?;

        // 1. login user and create session
        let user = User::fetch_and_validate(
            &db,
            &users[0].email,
            &users[0].password,
            users[0].totp.code()?,
        )
        .await?;
        let session = Session::create(&db, &user).await?;

        // 2. ask for dhcp leases in succession
        let _ip = dhcp.lease(&session).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        dhcp.release(&session).await?;

        let _ip = dhcp.lease(&session).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        dhcp.release(&session).await?;

        // 3. close session
        session.expire(&db).await?;

        Ok(())
    }

    #[tokio::test]
    async fn single_user_too_many_concurrent_leases() -> eyre::Result<()> {
        let (db, users) = crate::tests::setup().await?;
        let dhcp = create_dhcp_service(db.clone()).await?;

        // 1. login user and create session
        let user = User::fetch_and_validate(
            &db,
            &users[0].email,
            &users[0].password,
            users[0].totp.code()?,
        )
        .await?;
        let session = Session::create(&db, &user).await?;

        // 2. ask for dhcp lease
        let _ip = dhcp.lease(&session).await?;
        let r = dhcp.lease(&session).await;
        assert!(
            r.is_err(),
            "acquired two dhcp leases in one session, should only get one"
        );

        // 3. sleep for 1 second
        tokio::time::sleep(Duration::from_secs(1)).await;

        // 4. release dhcp lease
        dhcp.release(&session).await?;

        // 5. close session
        session.expire(&db).await?;

        Ok(())
    }

    #[tokio::test]
    async fn multi_user() -> eyre::Result<()> {
        let (db, users) = crate::tests::setup().await?;
        let dhcp = create_dhcp_service(db.clone()).await?;

        // 1. login user and create session
        let user0 = User::fetch_and_validate(
            &db,
            &users[0].email,
            &users[0].password,
            users[0].totp.code()?,
        )
        .await?;
        let mut u0_session = Session::create(&db, &user0).await?;

        let user1 = User::fetch_and_validate(
            &db,
            &users[1].email,
            &users[1].password,
            users[1].totp.code()?,
        )
        .await?;
        let mut u1_session = Session::create(&db, &user1).await?;

        // 2. ask for dhcp lease
        let u0_ip = dhcp.lease(&u0_session).await?;
        let u1_ip = dhcp.lease(&u1_session).await?;
        assert!(u0_ip != u1_ip, "user ip's should not match");

        // 3. release dhcp lease
        dhcp.release(&u0_session).await?;
        dhcp.release(&u1_session).await?;

        // 4. close session
        u0_session.expire(&db).await?;
        u1_session.expire(&db).await?;

        Ok(())
    }
}

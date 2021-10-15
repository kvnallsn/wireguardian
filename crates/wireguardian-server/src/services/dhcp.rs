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

        let ip = {
            // Note: this exists in a smaller scope to avoid potentially sending the RwLock
            // (available) across threads (which the compilier will complain about).  When this
            // scope ends, the lock is dropped and the db update can continue asynchronously

            // 2. lock in-memory db to avoid race conditions
            let mut available = self.0.write();

            // 3. find an available ip address
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

            // 4. mark ip as leased
            available.insert(ip, Some(id));

            // 5. return the newly leased IP
            ip
        };

        // 5. persist this lease in the db
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

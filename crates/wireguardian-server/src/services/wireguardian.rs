//! Wireguardian Server (Daemon)

use crate::{
    models::{Session, User},
    services::DhcpService,
};
use sqlx::sqlite::SqlitePool;
use tonic::{Request, Response, Status};
use wireguardian_proto::{
    wireguardian_server::{Wireguardian, WireguardianServer},
    ConnectReply, ConnectRequest, DisconnectReply, DisconnectRequest, LoginReply, LoginRequest,
    LogoutReply, LogoutRequest,
};

// TODO #3: Implement config file for wg device (to avoid requiring already created device)
pub struct WireguardianService {
    db: SqlitePool,
    dhcp: DhcpService,
}

impl WireguardianService {
    /// Creates a new `WireguardianService` that can be served via gRPC/HTTP2 backed by a sqlite
    /// database
    ///
    /// # Arguments
    /// * `db` - Sqlite Database used for auth/etc
    /// * `dhcp` - A dhcp service to issue IPv4 addresses when clients connect
    pub fn server(db: SqlitePool, dhcp: DhcpService) -> WireguardianServer<WireguardianService> {
        WireguardianServer::new(WireguardianService { db, dhcp })
    }

    /// Attempts to retrieve a session, returning an error if the session isn't found
    ///
    /// # Arguments
    /// * `token` - Unique identifier of session to fetch
    async fn get_session(&self, token: &str) -> Result<Session, Status> {
        let session = Session::fetch(&self.db, token).await.map_err(|error| {
            tracing::error!(?error, "failed to fetch session");
            Status::unauthenticated("user not logged in")
        })?;

        Ok(session)
    }
}

#[tonic::async_trait]
impl Wireguardian for WireguardianService {
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<LoginReply>, Status> {
        let request = request.into_inner();

        // 1. attempt to fetch and validate user credentials and totp
        let user =
            User::fetch_and_validate(&self.db, &request.email, &request.password, request.totp)
                .await
                .map_err(|error| {
                    tracing::error!(?error, "user failed to validate");
                    Status::unauthenticated("email or password incorrect")
                })?;

        // 2. create a session for the user
        let session = Session::create(&self.db, &user).await.map_err(|error| {
            tracing::error!(?error, "failed to create session");
            Status::unauthenticated("failed to create session")
        })?;

        // 3. send session id back to user
        let reply = LoginReply {
            token: session.id().to_owned(),
        };

        Ok(Response::new(reply))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutReply>, Status> {
        let request = request.into_inner();

        // 1. fetch session (validates token)
        let session = self.get_session(&request.token).await?;

        // 2. expire the session
        session.expire(&self.db).await.map_err(|error| {
            tracing::error!(?error, "failed to expire session");
            Status::unauthenticated("user not logged out")
        })?;

        let reply = LogoutReply { success: true };
        Ok(Response::new(reply))
    }

    async fn connect_vpn(
        &self,
        request: Request<ConnectRequest>,
    ) -> Result<Response<ConnectReply>, Status> {
        let request = request.into_inner();

        // 1. fetch session (validates token)
        let session = self.get_session(&request.token).await?;

        // 2. generate ip address (fake dhcp)
        let lease = self.dhcp.lease(&session).await.map_err(|error| {
            tracing::error!(?error);
            Status::resource_exhausted("no dhcp ips availabled")
        })?;

        // 3. add peer information to wireguard endpoint
        // TODO

        // 4. build response
        let reply = ConnectReply {
            ip: lease.to_string(),
            pubkey: "tbd".into(),
            endpoint: "".into(),
            allowed: "".into(),
        };

        Ok(Response::new(reply))
    }

    async fn disconnect_vpn(
        &self,
        request: Request<DisconnectRequest>,
    ) -> Result<Response<DisconnectReply>, Status> {
        let request = request.into_inner();

        // 1. fetch session (validates token)
        let session = self.get_session(&request.token).await?;

        // 2. release the ip
        self.dhcp.release(&session).await.map_err(|error| {
            tracing::error!(?error);
            Status::invalid_argument("bad request")
        })?;

        // 3. remove peer from wireguard endpoint
        // TODO

        // 4. build response
        let reply = DisconnectReply { success: true };

        Ok(Response::new(reply))
    }
}

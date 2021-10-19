//! Wireguardian Server (Daemon)

use crate::services::SessionService;
use color_eyre::eyre;
use tonic::{Request, Response, Status};
use wireguardian_device::{Device, Peer};
use wireguardian_proto::{
    wireguardian_server::{Wireguardian, WireguardianServer},
    ConnectReply, ConnectRequest, DisconnectReply, DisconnectRequest, LoginReply, LoginRequest,
    LogoutReply, LogoutRequest,
};

// TODO #3: Implement config file for wg device (to avoid requiring already created device)
pub struct WireguardianService {
    /// WireGuard device controlled by this service
    device: Device,

    /// Base64-encoded public key assigned to device
    public_key: String,

    /// Sessions store for users/groups/auth
    sessions: SessionService,
}

impl WireguardianService {
    /// Creates a new `WireguardianService` that can be served via gRPC/HTTP2 backed by a sqlite
    /// database
    ///
    /// # Arguments
    /// * `device` - WireGuard device controlled by this service
    /// * `sessions` - A session service to track user sessions
    pub fn server(
        device: Device,
        sessions: SessionService,
    ) -> eyre::Result<WireguardianServer<WireguardianService>> {
        // extract the public key from the wireguard device
        let public_key = device.public_key();
        let public_key = base64::encode(public_key.to_bytes());

        Ok(WireguardianServer::new(WireguardianService {
            device,
            public_key,
            sessions,
        }))
    }
}

#[tonic::async_trait]
impl Wireguardian for WireguardianService {
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<LoginReply>, Status> {
        let request = request.into_inner();

        // 1. validate user and create session (if successful)
        let session = self
            .sessions
            .login(&request.email, &request.password, request.totp)
            .await
            .map_err(|error| {
                tracing::error!(?error, "user failed to validate");
                Status::unauthenticated("email or password incorrect")
            })?;

        // 2. send session id back to user
        let reply = LoginReply {
            token: session.id().to_hyphenated().to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutReply>, Status> {
        let request = request.into_inner();

        self.sessions
            .logout(&request.token)
            .await
            .map_err(|error| {
                tracing::error!(?error, "failed to expire session");
                Status::internal("user not logged out")
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
        let session = self.sessions.get(&request.token).await.map_err(|error| {
            tracing::error!(?error, "session not found");
            Status::unauthenticated("user not logged in")
        })?;

        // 3. add peer information to wireguard endpoint
        let client_ip = session.ip();

        Peer::from_base64(request.pubkey)
            .map_err(|error| {
                tracing::error!(?error);
                Status::invalid_argument("parsing base64 pubkey failed")
            })?
            .allow_ip(client_ip)
            .add(&self.device)
            .map_err(|error| {
                tracing::error!(?error);
                Status::internal("failed to add peer")
            })?;

        let allowed_ips = self
            .device
            .allowed_ips()
            .into_iter()
            .map(|network| network.to_string())
            .collect::<Vec<_>>();

        // 4. build response
        let reply = ConnectReply {
            ip: client_ip.to_string(),
            pubkey: self.public_key.clone(),
            endpoint: self.device.endpoint().to_string(),
            allowed: allowed_ips,
        };

        Ok(Response::new(reply))
    }

    async fn disconnect_vpn(
        &self,
        request: Request<DisconnectRequest>,
    ) -> Result<Response<DisconnectReply>, Status> {
        let request = request.into_inner();

        // 1. fetch session (validates token)
        let _session = self.sessions.get(&request.token).await.map_err(|error| {
            tracing::error!(?error);
            Status::unauthenticated("user not logged out")
        })?;

        // 2. remove peer from wireguard endpoint
        Peer::from_base64(request.pubkey)
            .map_err(|error| {
                tracing::error!(?error);
                Status::invalid_argument("parsing base64 pubkey failed")
            })?
            .remove(&self.device);

        // 3. build response
        let reply = DisconnectReply { success: true };

        Ok(Response::new(reply))
    }
}

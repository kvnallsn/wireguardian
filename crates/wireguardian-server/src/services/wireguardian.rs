//! Wireguardian Server (Daemon)

use crate::services::SessionService;
use color_eyre::eyre;
use std::convert::TryInto;
use tonic::{Request, Response, Status};
use wireguard_rs::{
    configuration::{Configuration, WireGuardConfig},
    plt,
};
use wireguardian_proto::{
    wireguardian_server::{Wireguardian, WireguardianServer},
    ConnectReply, ConnectRequest, DisconnectReply, DisconnectRequest, LoginReply, LoginRequest,
    LogoutReply, LogoutRequest,
};
use x25519_dalek::PublicKey;

// TODO #3: Implement config file for wg device (to avoid requiring already created device)
pub struct WireguardianService {
    /// WireGuard device controlled by this service
    device: WireGuardConfig<plt::Tun, plt::UDP>,

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
        device: WireGuardConfig<plt::Tun, plt::UDP>,
        sessions: SessionService,
    ) -> eyre::Result<WireguardianServer<WireguardianService>> {
        // extract the public key from the wireguard device
        let public_key = match device
            .get_private_key()
            .map(|key| base64::encode(x25519_dalek::PublicKey::from(&key).to_bytes()))
        {
            Some(key) => key,
            None => eyre::bail!("private key not set"),
        };

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

                // TODO change error type
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
        let session = self.sessions.get(&request.token).await.map_err(|error| {
            tracing::error!(?error, "session not found");
            Status::unauthenticated("user not logged in")
        })?;

        // 3. add peer information to wireguard endpoint
        let client_pubkey: Vec<u8> = base64::decode(request.pubkey).unwrap();
        let client_pubkey: [u8; 32] = client_pubkey.try_into().unwrap();
        let client_pubkey: PublicKey = client_pubkey.into();
        let client_ip = session.ip();

        if !self.device.add_peer(&client_pubkey) {
            // TODO handle error
            // key already added
        }

        self.device
            .add_allowed_ip(&client_pubkey, client_ip.into(), 32);

        // 4. build response
        let reply = ConnectReply {
            ip: session.ip().to_string(),
            pubkey: self.public_key.clone(),
            endpoint: "127.0.0.1:5555".into(),
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
        let _session = self.sessions.get(&request.token).await.map_err(|error| {
            tracing::error!(?error);
            Status::unauthenticated("user not logged out")
        })?;

        // 2. remove peer from wireguard endpoint
        let client_pubkey: Vec<u8> = base64::decode(request.pubkey).unwrap();
        let client_pubkey: [u8; 32] = client_pubkey.try_into().unwrap();
        let client_pubkey: PublicKey = client_pubkey.into();

        self.device.remove_peer(&client_pubkey);

        // 3. build response
        let reply = DisconnectReply { success: true };

        Ok(Response::new(reply))
    }
}

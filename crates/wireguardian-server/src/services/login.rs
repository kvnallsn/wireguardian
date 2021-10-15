//! Wireguardian Server (Daemon)

use crate::models::{Session, User};
use sqlx::sqlite::SqlitePool;
use tonic::{Request, Response, Status};
use wireguardian_proto::{
    login_server::{Login, LoginServer},
    LoginReply, LoginRequest,
};

// TODO #3: Implement config file for wg device (to avoid requiring already created device)
#[derive(Debug)]
pub struct LoginService {
    db: SqlitePool,
}

impl LoginService {
    /// Creates a new `LoginService` that can be served via gRPC/HTTP2 backed by a sqlite
    /// database
    pub fn server(db: SqlitePool) -> LoginServer<LoginService> {
        LoginServer::new(LoginService { db })
    }
}

#[tonic::async_trait]
impl Login for LoginService {
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
}

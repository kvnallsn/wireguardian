//! Wireguardian Server (Daemon)

use color_eyre::eyre;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Input, Password};
use std::io::Write;
use tonic::transport::{Channel, Endpoint, Uri};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use x25519_dalek::{PublicKey, StaticSecret};

use wireguardian_proto::{
    wireguardian_client::WireguardianClient, ConnectRequest, DisconnectRequest, LoginRequest,
    LogoutRequest,
};

struct Client {
    /// gRPC client
    client: WireguardianClient<Channel>,

    /// present if user has authenticated with the gRPC service
    auth_token: Option<String>,

    /// private key associated with this client
    private_key: StaticSecret,
}

#[derive(Debug, thiserror::Error)]
enum ClientError {
    #[error("unauthenticated")]
    Unauthenticated,

    #[error("{0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("{0}")]
    Grpc(#[from] tonic::Status),
}

impl Client {
    pub async fn new(endpoint: impl Into<Endpoint>) -> Result<Self, ClientError> {
        let rng = rand::thread_rng();
        let private_key = StaticSecret::new(rng);

        let client = WireguardianClient::connect(endpoint).await?;

        Ok(Self {
            client,
            auth_token: None,
            private_key,
        })
    }

    /// Returns true if the user has authenticated with the gPRC service
    fn is_authenticated(&self) -> bool {
        self.auth_token.is_some()
    }

    fn public_key(&self) -> String {
        let public_key = PublicKey::from(&self.private_key);
        base64::encode(public_key.to_bytes())
    }

    async fn login(
        &mut self,
        email: String,
        password: String,
        totp: u32,
    ) -> Result<(), ClientError> {
        if self.auth_token.is_some() {
            // already logged in
            // TODO should we validate the token?

            return Ok(());
        }

        let request = tonic::Request::new(LoginRequest {
            email,
            password,
            totp,
        });

        tracing::info!("sending login request");
        let response = self.client.login(request).await?;
        let response = response.into_inner();
        self.auth_token = Some(response.token);
        tracing::info!("log in successful");

        Ok(())
    }

    async fn connect(&mut self) -> Result<(), ClientError> {
        if let Some(token) = &self.auth_token {
            let request = tonic::Request::new(ConnectRequest {
                token: token.to_owned(),
                pubkey: self.public_key(),
            });

            tracing::info!("sending connect request");
            let response = self.client.connect_vpn(request).await?;
            let response = response.into_inner();
            tracing::info!("connected: {:#?}", response);
            Ok(())
        } else {
            Err(ClientError::Unauthenticated)
        }
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        if let Some(token) = &self.auth_token {
            let request = tonic::Request::new(DisconnectRequest {
                token: token.to_owned(),
                pubkey: self.public_key(),
            });

            tracing::info!("sending disconnect request");
            let response = self.client.disconnect_vpn(request).await?;
            let _response = response.into_inner();
            tracing::info!("disconnected");

            Ok(())
        } else {
            Err(ClientError::Unauthenticated)
        }
    }

    async fn logout(&mut self) -> Result<(), ClientError> {
        if let Some(token) = &self.auth_token {
            let request = tonic::Request::new(LogoutRequest {
                token: token.to_owned(),
            });

            tracing::info!("sending logout request");
            let response = self.client.logout(request).await?;
            let _response = response.into_inner();
            tracing::info!("logged out");

            Ok(())
        } else {
            Err(ClientError::Unauthenticated)
        }
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // init logging
    FmtSubscriber::builder().with_max_level(Level::INFO).init();
    color_eyre::install()?;

    let mut term = Term::stdout();
    let theme = ColorfulTheme::default();

    let endpoint: Uri = Input::with_theme(&theme)
        .with_prompt("Server")
        .interact_text()?;

    let mut client = Client::new(endpoint.clone()).await?;
    writeln!(
        &mut term,
        "Connected to wireguardian endpoint: {}",
        endpoint
    )?;

    'repl: loop {
        // repl
        write!(&mut term, "> ")?;
        let cmd = term.read_line()?;

        let mut args = cmd.split_whitespace();
        match args.next() {
            Some("login") => {
                let email: String = Input::with_theme(&theme)
                    .with_prompt("Email")
                    .interact_text()?;

                let password: String = Password::with_theme(&theme)
                    .with_prompt("Password")
                    .interact()?;

                let totp: u32 = Input::with_theme(&theme)
                    .with_prompt("2FA Code")
                    .interact_text()?;

                match client.login(email, password, totp).await {
                    Ok(()) => {
                        writeln!(&mut term, "Successfully logged in")?;
                    }
                    Err(error) => {
                        tracing::error!(?error, "failed to log in");
                    }
                }
            }
            Some("connect") => match client.connect().await {
                Ok(()) => {
                    writeln!(&mut term, "Successfully connected")?;
                }
                Err(ClientError::Unauthenticated) => {
                    writeln!(&mut term, "Unauthenticated -- Please login first")?;
                }
                Err(error) => {
                    tracing::error!(?error, "failed to connect");
                }
            },
            Some("disconnect") => match client.disconnect().await {
                Ok(()) => {
                    writeln!(&mut term, "Successfully disconnected")?;
                }
                Err(ClientError::Unauthenticated) => {
                    writeln!(&mut term, "Unauthenticated -- Please login first")?;
                }
                Err(error) => {
                    tracing::error!(?error, "failed to disconnect");
                }
            },
            Some("logout") => match client.logout().await {
                Ok(()) => {
                    writeln!(&mut term, "Successfully logged out")?;
                }
                Err(ClientError::Unauthenticated) => {
                    writeln!(&mut term, "Unauthenticated -- Please login first")?;
                }
                Err(error) => {
                    tracing::error!(?error, "failed to logout");
                }
            },
            Some("help" | "?") => {
                writeln!(&mut term, "Commands:")?;
                writeln!(&mut term, "login         Log into a wireguardian endpoint")?;
                writeln!(&mut term, "connect       Connect to the vpn service")?;
                writeln!(&mut term, "diconnect     Disconnect from the vpn service")?;
                writeln!(&mut term, "logout        Log out of wireguardian endpoint")?;
                writeln!(&mut term, "quit          Exits, logouts out if needed")?;
                writeln!(&mut term, "")?;
            }
            Some("stop" | "quit" | "exit") => break 'repl,
            _ => writeln!(&mut term, "invalid command")?,
        }
    }

    // ensure we've disconnected/logged out before quitting
    match client.logout().await {
        Ok(()) => { /* do nothing */ }
        Err(ClientError::Unauthenticated) => { /* do nothing */ }
        Err(error) => tracing::error!(?error, "failed to logout"),
    }

    Ok(())
}

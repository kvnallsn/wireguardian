//! Wireguardian Server (Daemon)

use dialoguer::{theme::ColorfulTheme, Input};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use wireguardian_proto::{
    wireguardian_client::WireguardianClient, ConnectRequest, DisconnectRequest, LoginRequest,
    LogoutRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // init logging
    FmtSubscriber::builder().with_max_level(Level::INFO).init();

    let mut client = WireguardianClient::connect("http://[::1]:1337").await?;

    let totp: u32 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("TOTP")
        .interact_text()
        .unwrap();

    let request = tonic::Request::new(LoginRequest {
        email: "trike@example.com".into(),
        password: "hunter42".into(),
        totp,
    });

    tracing::info!("sending login request");
    let response = client.login(request).await?;
    let response = response.into_inner();
    let auth_token = response.token;
    tracing::info!("logged in with auth token {}", auth_token);

    tracing::info!("sleeping for two seconds");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let request = tonic::Request::new(ConnectRequest {
        token: auth_token.clone(),
        pubkey: "tbd".into(),
    });

    tracing::info!("sending connect request");
    let response = client.connect_vpn(request).await?;
    let response = response.into_inner();
    tracing::info!("connected with ip {}", response.ip);

    tracing::info!("sleeping for two seconds");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let request = tonic::Request::new(DisconnectRequest {
        token: auth_token.clone(),
        pubkey: "tbd".into(),
    });

    tracing::info!("sending disconnect request");
    let response = client.disconnect_vpn(request).await?;
    let _response = response.into_inner();
    tracing::info!("disconnected");

    tracing::info!("sleeping for two seconds");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let request = tonic::Request::new(LogoutRequest {
        token: auth_token.clone(),
    });

    tracing::info!("sending logout request");
    let response = client.logout(request).await?;
    let _response = response.into_inner();
    tracing::info!("logged out");

    Ok(())
}

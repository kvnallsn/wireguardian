//! Wireguardian Server (Daemon)

use clap::Clap;
use color_eyre::eyre;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use std::path::Path;
use tonic::transport::Server;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

pub mod cli;
pub mod config;
pub mod device;
pub mod models {
    mod user;
    pub use user::User;

    mod session;
    pub use session::Session;

    mod totp;
    pub use totp::TotpParams;

    #[cfg(test)]
    mod tests;
}
pub mod otp;
pub mod services {
    mod session;
    pub use session::SessionService;

    mod wireguardian;
    pub use wireguardian::WireguardianService;
}
pub mod shell;

#[cfg(test)]
mod tests;

/// Opens the backend database, running any necessary migrations
///
///
/// # Arguments
/// * `path` - Path to sqlite3 database
///
/// # Errors
/// * Database fails to initialize / open
async fn open_database(path: impl AsRef<Path>) -> eyre::Result<SqlitePool> {
    // connect to the backing sqlite database
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);

    let pool = SqlitePoolOptions::new()
        .min_connections(1)
        .max_connections(1)
        .connect_with(options)
        .await?;

    // run any pending migraionts
    sqlx::migrate!().run(&pool).await?;

    Ok(pool)
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    use cli::SubCommand;
    use dialoguer::{Input, Password};

    let opts = cli::Opts::parse();

    // init logging
    let level = match opts.verbosity {
        0 => Level::ERROR,
        1 => Level::WARN,
        2 => Level::INFO,
        3 => Level::DEBUG,
        _ => Level::TRACE,
    };
    FmtSubscriber::builder().with_max_level(level).init();

    // init error/panic handling
    color_eyre::install()?;

    let theme = dialoguer::theme::ColorfulTheme::default();

    let db = open_database(&opts.db).await?;

    match opts.subcmd {
        SubCommand::Run { config } => {
            let cfg = config::WireguardianConfig::load(config)?;

            // 1. start wireguard device based on args
            let _wg = device::create(cfg.device)?;

            // 2. start session & wireguardian grpc service
            tracing::info!(?cfg.dhcp, "starting session service");
            let session_svc = services::SessionService::new(db, cfg.dhcp).await?;

            tracing::info!(?cfg.rpc.listen, "starting wireguardian service");
            let svc = services::WireguardianService::server(session_svc);

            // 3. wait for shutdown or ctrl-c signal
            tokio::select! {
                res = Server::builder().add_service(svc).serve(cfg.rpc.listen) => match res {
                    Ok(_) => tracing::info!("hyper/tonic server stopped"),
                    Err(error) => tracing::error!(?error, "failed to serve wireguardian grpc")
                },

                res = tokio::signal::ctrl_c() => match res {
                    Ok(_) => tracing::info!("caught ctrl-c, shutting down"),
                    Err(error) => tracing::error!(?error, "error registring ctrl-c handler")
                }
            }
        }
        SubCommand::AddUser => {
            let username: String = Input::with_theme(&theme)
                .with_prompt("Username")
                .allow_empty(false)
                .interact()?;

            let email: String = Input::with_theme(&theme)
                .with_prompt("Email")
                .allow_empty(false)
                .interact()?;

            let password: String = Password::with_theme(&theme)
                .with_prompt("Password")
                .with_confirmation("Confirm", "Password Mismatch")
                .interact()?;

            // generate totp code
            let totp_params = models::TotpParams::generate();
            let uri = totp_params.uri("wireguardian");

            println!("TOTP:");
            qr2term::print_qr(uri)?;
            println!("");

            let code: u32 = Input::with_theme(&theme)
                .with_prompt("Confirm TOTP Code")
                .allow_empty(false)
                .interact_text()?;

            totp_params.validate(code)?;

            println!("code validated, saving user");

            models::User::create(&db, username, email, password, totp_params).await?;

            println!("user saved");
        }
    }

    Ok(())
}

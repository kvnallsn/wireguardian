//! Command Line Options and Arguments

use clap::Clap;
use std::path::PathBuf;

#[derive(Clap)]
pub struct Opts {
    /// A level of verbosity, and can be used multiple times
    #[clap(short, long, parse(from_occurrences))]
    pub verbosity: u8,

    /// Path to the wireguardian database
    #[clap(short, long, default_value = "wg.db")]
    pub db: PathBuf,

    #[clap(subcommand)]
    pub subcmd: SubCommand,
}

#[derive(Clap)]
pub enum SubCommand {
    /// Runs the wireguardian server
    Run {
        /// Path to configuration file for wireguardian server
        #[clap(short, long, default_value = "wg.toml")]
        config: PathBuf,
    },

    /// Adds a new user to the system
    AddUser,
}

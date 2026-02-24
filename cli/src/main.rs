mod commands;
mod dotenv;
mod fanout;
mod github;
mod identity;
mod session;
mod storage;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "shenan", about = "Securely share secrets using SSH keys")]
struct Cli {
    /// Enable verbose output (debug logging)
    #[arg(short, long, global = true, env = "SHENAN_VERBOSE")]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize — discover local SSH keys, select identity
    Init,

    /// Send secrets to another user
    Send {
        /// Recipient in format github:<username>
        #[arg(long)]
        to: String,

        /// KEY=value pairs
        #[arg(trailing_var_arg = true)]
        key_values: Vec<String>,

        /// Read secrets from a .env file
        #[arg(long)]
        from_file: Option<PathBuf>,

        /// Relay URL override (e.g. ws://127.0.0.1:9000)
        #[arg(long, env = "SHENAN_RELAY")]
        relay: Option<String>,
    },

    /// Receive secrets from another user
    Receive {
        /// Sender in format github:<username>
        #[arg(long)]
        from: String,

        /// Write secrets to a file (default: .env in current directory)
        #[arg(long)]
        out: Option<PathBuf>,

        /// Overwrite the output file instead of appending to it
        #[arg(long)]
        overwrite: bool,

        /// Relay URL override (e.g. ws://127.0.0.1:9000)
        #[arg(long, env = "SHENAN_RELAY")]
        relay: Option<String>,
    },

    /// Manage trusted senders
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },

    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum TrustAction {
    /// Add a trusted sender (format: github:<username>)
    Add { target: String },
    /// Remove a trusted sender
    Remove { target: String },
    /// List trusted senders
    List,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Set a config value
    Set { key: String, value: String },
    /// Get a config value
    Get { key: String },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let default_level = if cli.verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level)),
        )
        .init();

    let result = match cli.command {
        Commands::Init => commands::init::run().await,
        Commands::Send {
            to,
            key_values,
            from_file,
            relay,
        } => {
            let stdin =
                !atty::is(atty::Stream::Stdin) && from_file.is_none() && key_values.is_empty();
            commands::send::run(&to, key_values, from_file, stdin, relay).await
        }
        Commands::Receive {
            from,
            out,
            overwrite,
            relay,
        } => commands::receive::run(&from, out, overwrite, relay).await,
        Commands::Trust { action } => match action {
            TrustAction::Add { target } => commands::trust::add(&target),
            TrustAction::Remove { target } => commands::trust::remove(&target),
            TrustAction::List => commands::trust::list(),
        },
        Commands::Config { action } => match action {
            ConfigAction::Set { key, value } => commands::config::set(&key, &value),
            ConfigAction::Get { key } => commands::config::get(&key),
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

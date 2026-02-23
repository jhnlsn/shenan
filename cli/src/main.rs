mod commands;
mod dotenv;
mod github;
mod identity;
mod session;
mod storage;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "shenan", about = "Securely share secrets using SSH keys")]
struct Cli {
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
    },

    /// Receive secrets from another user
    Receive {
        /// Sender in format github:<username>
        #[arg(long)]
        from: String,

        /// Write secrets to a file (default: stdout)
        #[arg(long)]
        out: Option<PathBuf>,

        /// Merge with existing file instead of overwriting
        #[arg(long)]
        merge: bool,
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

    let result = match cli.command {
        Commands::Init => commands::init::run().await,
        Commands::Send {
            to,
            key_values,
            from_file,
        } => {
            let stdin = !atty::is(atty::Stream::Stdin) && from_file.is_none() && key_values.is_empty();
            commands::send::run(&to, key_values, from_file, stdin).await
        }
        Commands::Receive { from, out, merge } => {
            commands::receive::run(&from, out, merge).await
        }
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

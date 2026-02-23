mod admission;
mod auth;
mod cleanup;
mod config;
mod connection;
mod github;
mod pipe;
mod ratelimit;
mod server;
mod state;

use clap::Parser;
use config::{RelayArgs, RelayConfig};

#[tokio::main]
async fn main() {
    let args = RelayArgs::parse();
    let config = RelayConfig::from(args);

    if let Err(e) = server::run(config).await {
        eprintln!("relay error: {e}");
        std::process::exit(1);
    }
}

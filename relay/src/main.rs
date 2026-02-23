use clap::Parser;
use shenan_relay::config::{RelayArgs, RelayConfig};

#[tokio::main]
async fn main() {
    let args = RelayArgs::parse();
    let config = RelayConfig::from(args);

    if let Err(e) = shenan_relay::server::run(config).await {
        eprintln!("relay error: {e}");
        std::process::exit(1);
    }
}

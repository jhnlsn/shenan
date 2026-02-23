use clap::Parser;
use shenan_relay::config::{RelayArgs, RelayConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let args = RelayArgs::parse();
    let config = RelayConfig::from(args);

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.log_level)),
        )
        .init();

    if let Err(e) = shenan_relay::server::run(config).await {
        tracing::error!("relay error: {e}");
        std::process::exit(1);
    }
}

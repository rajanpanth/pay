use clap::Parser;
use pay_cloud::AppState;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// pay-cloud v0: browser onboarding for the pay CLI.
#[derive(Parser)]
#[command(name = "pay-cloud", version, about)]
struct Args {
    /// Interface to bind.
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// TCP port to listen on.
    #[arg(long, default_value_t = 8402)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let addr = format!("{}:{}", args.bind, args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let local = listener.local_addr()?;
    info!(url = %format!("http://{local}"), "pay-cloud listening");

    let app = pay_cloud::router(AppState::new()).layer(TraceLayer::new_for_http());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}

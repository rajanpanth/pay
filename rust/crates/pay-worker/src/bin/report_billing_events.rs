//! `report-billing-events` — drains the `pay:billing:events` Redis Stream
//! (populated by `pay-proxy`'s hosts via `record_exchange`, one entry per
//! metered exchange regardless of payment scheme) and reports each batch
//! onward.
//!
//! The final export destination is intentionally not wired up yet: whether a
//! self-hosted, analytics-only Apigee Adapter feed is acceptable for a
//! partner's billing meter (vs. requiring traffic through their fully-hosted
//! proxy) is still an open question with that partner. Until it's answered,
//! this job proves the pipeline end-to-end — reading real events, decoding
//! them, and acking them — with the actual outbound call as the one place
//! (`report`, below) that needs to change once that's resolved.
//!
//! Env:
//!   PAY_BILLING_REDIS_URL             Redis connection URL (required)
//!   RUN_ONCE                          default true; set false for the
//!                                     continuous Cloud Run service form
//!   BILLING_EXPORT_INTERVAL_SECONDS   poll interval in continuous mode
//!                                     (default 10)
//!   BILLING_EXPORT_BATCH_SIZE         max entries per XREADGROUP call
//!                                     (default 200)
//!   PORT                              health-check port in continuous mode
//!                                     (default 8080)

use std::time::Duration;

use axum::Router;
use axum::routing::get;
use pay_worker::error::JobError;
use pay_worker::telemetry;
use redis::Value;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Redis Stream key `pay-proxy` hosts `XADD` billing events into (mirrors
/// the producer-side constant in `pay::commands::server::billing_export`).
const STREAM_KEY: &str = "pay:billing:events";
const CONSUMER_GROUP: &str = "report-billing-events";
const DEFAULT_INTERVAL_SECONDS: u64 = 10;
const DEFAULT_BATCH_SIZE: u64 = 200;
const DEFAULT_PORT: u64 = 8080;

/// Mirrors `pay_core::BillingEvent`'s JSON shape. Deliberately not a shared
/// type: this job is the one place allowed to know a downstream billing
/// reporting pipeline exists at all, and pulling in pay-core's full
/// dependency tree just to reuse one struct would be a heavier coupling
/// than a documented wire-format convention.
#[derive(Debug, serde::Deserialize)]
struct BillingEvent {
    method: String,
    path: String,
    status: u16,
    #[allow(dead_code)] // carried through for a future export payload
    ms: u64,
    scheme: String,
    charge_status: String,
    currency: Option<String>,
    amount_usd: Option<f64>,
    unit: Option<String>,
    quantity: Option<u64>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let _telemetry = telemetry::init("pay-jobs-report-billing-events");

    let redis_url = match std::env::var("PAY_BILLING_REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            return record_startup_failure(JobError::Config(
                "PAY_BILLING_REDIS_URL must be set".to_string(),
            ));
        }
    };
    let run_once = match parse_bool_env("RUN_ONCE", true) {
        Ok(value) => value,
        Err(error) => return record_startup_failure(error),
    };
    let batch_size = match parse_u64_env("BILLING_EXPORT_BATCH_SIZE", DEFAULT_BATCH_SIZE) {
        Ok(value) => value,
        Err(error) => return record_startup_failure(error),
    };

    let mut conn = match connect(&redis_url).await {
        Ok(conn) => conn,
        Err(error) => return record_startup_failure(error),
    };
    if let Err(error) = ensure_group(&mut conn).await {
        return record_startup_failure(error);
    }

    if run_once {
        return match drain_once(&mut conn, batch_size).await {
            Ok(count) => {
                info!(
                    count,
                    event = "report_billing_events_exit",
                    outcome = "ok",
                    "drained available billing events"
                );
                std::process::ExitCode::SUCCESS
            }
            Err(error) => record_startup_failure(error),
        };
    }

    let interval_seconds = match parse_u64_env(
        "BILLING_EXPORT_INTERVAL_SECONDS",
        DEFAULT_INTERVAL_SECONDS,
    ) {
        Ok(0) => {
            return record_startup_failure(JobError::Config(
                "BILLING_EXPORT_INTERVAL_SECONDS must be greater than zero".into(),
            ));
        }
        Ok(value) => value,
        Err(error) => return record_startup_failure(error),
    };
    let port = match parse_u64_env("PORT", DEFAULT_PORT) {
        Ok(port) if u16::try_from(port).is_ok() => port as u16,
        Ok(_) => {
            return record_startup_failure(JobError::Config(
                "PORT must be between 0 and 65535".into(),
            ));
        }
        Err(error) => return record_startup_failure(error),
    };

    let address = format!("0.0.0.0:{port}");
    let listener = match tokio::net::TcpListener::bind(&address).await {
        Ok(listener) => listener,
        Err(error) => {
            return record_startup_failure(JobError::Config(format!(
                "failed to bind worker health endpoint on {address}: {error}"
            )));
        }
    };
    let app = Router::new().route("/health", get(|| async { "ok" }));
    info!(
        %address,
        interval_seconds,
        "continuous report-billing-events worker starting"
    );

    let cancel = CancellationToken::new();
    let server_shutdown = cancel.clone();
    let cancel_on_server_exit = cancel.clone();
    let server = tokio::spawn(async move {
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(server_shutdown.cancelled_owned())
            .await;
        cancel_on_server_exit.cancel();
        result
    });
    let cancel_on_signal = cancel.clone();
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        info!("report-billing-events shutdown signal received");
        cancel_on_signal.cancel();
    });

    let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }
        match drain_once(&mut conn, batch_size).await {
            Ok(count) if count > 0 => info!(count, "reported billing events"),
            Ok(_) => {}
            Err(error) => warn!(%error, "billing-event drain failed; will retry next tick"),
        }
        if cancel.is_cancelled() {
            break;
        }
    }
    cancel.cancel();

    let server_result = server.await;
    if !signal.is_finished() {
        signal.abort();
    }
    let _ = signal.await;

    match server_result {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        Ok(Err(error)) => {
            error!(%error, "report-billing-events health server failed");
            std::process::ExitCode::FAILURE
        }
        Err(error) => {
            error!(%error, "report-billing-events health server task failed");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn connect(redis_url: &str) -> Result<redis::aio::ConnectionManager, JobError> {
    let client =
        redis::Client::open(redis_url).map_err(|error| JobError::Config(format!("Redis client: {error}")))?;
    client
        .get_connection_manager()
        .await
        .map_err(|error| JobError::Config(format!("Redis connect: {error}")))
}

/// Idempotent: `BUSYGROUP` (the group already exists from a prior run) is
/// not an error.
async fn ensure_group(conn: &mut redis::aio::ConnectionManager) -> Result<(), JobError> {
    let result: Result<String, redis::RedisError> = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(STREAM_KEY)
        .arg(CONSUMER_GROUP)
        .arg("0")
        .arg("MKSTREAM")
        .query_async(conn)
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.to_string().contains("BUSYGROUP") => Ok(()),
        Err(error) => Err(JobError::Config(format!("Redis XGROUP CREATE: {error}"))),
    }
}

/// Read one batch via the consumer group, report and `XACK` whatever decoded
/// cleanly. A malformed entry is acked anyway (logged, not retried) rather
/// than left to block the group forever on a poison message. Returns the
/// number of entries acknowledged.
async fn drain_once(
    conn: &mut redis::aio::ConnectionManager,
    batch_size: u64,
) -> Result<usize, JobError> {
    let consumer = format!("{}-{}", std::process::id(), unix_nanos());
    let reply: redis::streams::StreamReadReply = redis::cmd("XREADGROUP")
        .arg("GROUP")
        .arg(CONSUMER_GROUP)
        .arg(&consumer)
        .arg("COUNT")
        .arg(batch_size)
        .arg("STREAMS")
        .arg(STREAM_KEY)
        .arg(">")
        .query_async(conn)
        .await
        .map_err(|error| JobError::Config(format!("Redis XREADGROUP: {error}")))?;

    let mut ids_to_ack = Vec::new();
    for stream_key in &reply.keys {
        for entry in &stream_key.ids {
            match decode_entry(entry) {
                Some(Ok(event)) => report(&event),
                Some(Err(error)) => {
                    warn!(%error, id = %entry.id, "failed to decode billing event");
                }
                None => {
                    warn!(id = %entry.id, "billing-event entry missing its 'event' field");
                }
            }
            ids_to_ack.push(entry.id.clone());
        }
    }
    if ids_to_ack.is_empty() {
        return Ok(0);
    }

    let mut ack = redis::cmd("XACK");
    ack.arg(STREAM_KEY).arg(CONSUMER_GROUP);
    for id in &ids_to_ack {
        ack.arg(id);
    }
    let _: i64 = ack
        .query_async(conn)
        .await
        .map_err(|error| JobError::Config(format!("Redis XACK: {error}")))?;
    Ok(ids_to_ack.len())
}

/// `None` if the entry carries no `event` field at all; `Some(Err(_))` if it
/// does but isn't valid UTF-8 JSON matching `BillingEvent`.
fn decode_entry(entry: &redis::streams::StreamId) -> Option<Result<BillingEvent, serde_json::Error>> {
    let raw = match entry.map.get("event")? {
        Value::BulkString(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        Value::SimpleString(s) => s.clone(),
        _ => return None,
    };
    Some(serde_json::from_str(&raw))
}

/// TODO(apigee): this is the one place that needs to change once the
/// partner confirms whether the self-hosted, analytics-only Adapter feed is
/// acceptable for their billing meter. For now this proves the pipeline
/// works end-to-end against real, non-mocked billing events.
fn report(event: &BillingEvent) {
    info!(
        monotonic_counter.pay_billing_events_reported_total = 1_u64,
        method = %event.method,
        path = %event.path,
        status = event.status,
        scheme = %event.scheme,
        charge_status = %event.charge_status,
        currency = event.currency.as_deref(),
        amount_usd = event.amount_usd,
        unit = event.unit.as_deref(),
        quantity = event.quantity,
        "billing event"
    );
}

fn unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

fn record_startup_failure(error: JobError) -> std::process::ExitCode {
    error!(
        monotonic_counter.pay_billing_export_startup_failures_total = 1_u64,
        event = "report_billing_events_exit",
        outcome = "aborted",
        %error,
        "report-billing-events failed to start"
    );
    std::process::ExitCode::FAILURE
}

fn parse_bool_env(name: &str, default: bool) -> Result<bool, JobError> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| JobError::Config(format!("{name} must be true or false"))),
        Err(_) => Ok(default),
    }
}

fn parse_u64_env(name: &str, default: u64) -> Result<u64, JobError> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| JobError::Config(format!("{name} must be an integer"))),
        Err(_) => Ok(default),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

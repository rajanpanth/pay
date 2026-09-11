//! Non-blocking billing-event export.
//!
//! `record_exchange` hands a completed [`pay_core::BillingEvent`] to
//! [`BillingSink::report`], a cheap, bounded, drop-on-full channel send —
//! never anything that could stall the request/response cycle that produced
//! it. A background task drains that channel and `XADD`s each event into a
//! Redis Stream (`pay-worker`'s `report-billing-events` job reads from
//! there, batches, and ships them onward). Entirely opt-in: unset
//! `PAY_BILLING_REDIS_URL` and `BillingSink::from_env` returns `None`, at
//! which point `record_exchange` pays nothing beyond an `Option` check.

use pay_core::BillingEvent;
use tokio::sync::mpsc;

/// Redis Stream key billing events are `XADD`ed into. `pay-worker`'s
/// consumer job reads from the same key.
const STREAM_KEY: &str = "pay:billing:events";

/// Bounded channel capacity between `record_exchange` (producer, in the hot
/// path) and the background Redis writer (consumer). A full channel means
/// the writer is falling behind Redis or Redis is down — dropping the event
/// is the correct failure mode, not blocking the request that produced it.
const CHANNEL_CAPACITY: usize = 4096;

#[derive(Clone)]
pub struct BillingSink {
    tx: mpsc::Sender<BillingEvent>,
}

impl BillingSink {
    /// Starts the background Redis writer if `PAY_BILLING_REDIS_URL` is set
    /// and non-empty. Returns `None` otherwise — the feature is entirely
    /// opt-in per deployment.
    pub fn from_env() -> Option<Self> {
        let redis_url = std::env::var("PAY_BILLING_REDIS_URL")
            .ok()
            .filter(|v| !v.is_empty())?;
        Some(Self::spawn(redis_url))
    }

    fn spawn(redis_url: String) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(drain(redis_url, rx));
        Self { tx }
    }

    /// Report one metered exchange. Non-blocking: drops the event and logs
    /// (never panics, never awaits) if the channel is full or the writer
    /// task has exited.
    pub fn report(&self, event: BillingEvent) {
        if self.tx.try_send(event).is_err() {
            tracing::warn!(
                metric = "pay_billing_events_dropped_total",
                "billing-event channel full or closed; dropping event"
            );
        }
    }
}

/// Owns the Redis connection and the receiving half of the channel for the
/// lifetime of the process. Runs until the last [`BillingSink`] clone (and
/// thus every sender) is dropped.
async fn drain(redis_url: String, mut rx: mpsc::Receiver<BillingEvent>) {
    let mut conn = match connect(&redis_url).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::error!(
                %error,
                "billing-event export: failed to connect to Redis; every reported event will be dropped for the life of this process"
            );
            // Keep receiving (and discarding) so `try_send` on the producer
            // side sees a live channel rather than immediately erroring —
            // either way the event is dropped, but this keeps the failure
            // mode uniform (always "channel full/gone", never a distinct
            // "no consumer" branch the producer has to reason about).
            while rx.recv().await.is_some() {}
            return;
        }
    };
    while let Some(event) = rx.recv().await {
        let payload = match serde_json::to_string(&event) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::error!(%error, "billing-event export: failed to serialize event");
                continue;
            }
        };
        let result: Result<String, redis::RedisError> = redis::cmd("XADD")
            .arg(STREAM_KEY)
            .arg("*")
            .arg("event")
            .arg(payload)
            .query_async(&mut conn)
            .await;
        if let Err(error) = result {
            tracing::warn!(%error, "billing-event export: XADD failed; dropping event");
        }
    }
}

async fn connect(redis_url: &str) -> Result<redis::aio::ConnectionManager, redis::RedisError> {
    let client = redis::Client::open(redis_url)?;
    client.get_connection_manager().await
}

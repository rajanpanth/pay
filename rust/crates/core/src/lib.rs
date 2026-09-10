// Shared modules
pub mod accounts;
mod b58;
pub mod config;
pub mod error;
pub mod explorer;
pub mod instructions;
pub mod keystore;
pub mod signer;
pub mod skills;
pub mod user_agent;

// Client modules (CLI)
pub mod client;

// Flat re-exports so callers can use `pay_core::mpp`, `pay_core::runner`, etc.
pub use client::balance;
pub use client::fetch;
pub use client::mpp;
pub use client::runner;
pub use client::runner::{
    run_curl, run_curl_with_headers, run_httpie, run_httpie_with_headers, run_wget,
    run_wget_with_headers,
};
pub use client::sandbox;
pub use client::send;
pub use client::session;
pub use client::x402;

// Server modules (gateway proxy)
pub mod server;

pub use config::{Config, LogFormat};
pub use error::{Error, Result};
pub use server::{AccountingKey, AccountingStore, InMemoryStore, current_period};
pub use user_agent::ClientApp;

#[cfg(feature = "server")]
pub use pay_kit::mpp as solana_mpp;
#[cfg(feature = "server")]
use pay_kit::mpp::server::Mpp;
#[cfg(feature = "server")]
use pay_types::metering::ApiSpec;
#[cfg(feature = "server")]
use std::sync::Arc;

/// Trait that the application state must implement for the payment middleware.
#[cfg(feature = "server")]
pub trait PaymentState: Clone + Send + Sync + 'static {
    fn apis(&self) -> &[ApiSpec];
    fn mpp(&self) -> Option<&Mpp>;
    fn mpps(&self) -> Vec<&Mpp> {
        self.mpp().into_iter().collect()
    }
    fn browser_rpc_url(&self) -> Option<&str> {
        None
    }
    fn session_mpp(&self) -> Option<&server::session::SessionMpp> {
        None
    }
    fn session_mpp_handle(&self) -> Option<Arc<server::session::SessionMpp>> {
        None
    }
    fn session_mpps(&self) -> Vec<&server::session::SessionMpp> {
        self.session_mpp().into_iter().collect()
    }
    fn session_mpp_handles(&self) -> Vec<Arc<server::session::SessionMpp>> {
        self.session_mpp_handle().into_iter().collect()
    }
    fn fee_payer_wallet(&self) -> Option<&server::telemetry::FeePayerWallet> {
        None
    }
    /// Operator's fee-payer signer, when configured. The subscription
    /// middleware needs it at verify time to co-sign the activation
    /// transaction; charge / session paths construct their own MPP
    /// instances at startup and don't ask for it through this trait.
    fn fee_payer_signer(&self) -> Option<Arc<dyn pay_kit::mpp::solana_keychain::SolanaSigner>> {
        None
    }

    /// x402 `exact` handler, when the server accepts x402 payments.
    fn x402(&self) -> Option<&pay_kit::x402::server::X402> {
        None
    }
    /// x402 `upto` (usage-based) handler, when configured with an operator signer.
    fn x402_upto(&self) -> Option<&pay_kit::x402::server::X402Upto> {
        None
    }
    /// x402 `batch-settlement` handler, when configured with an operator signer.
    fn x402_batch(&self) -> Option<&pay_kit::x402::server::X402BatchSettlement> {
        None
    }

    /// Record a completed proxied HTTP exchange for the Payment Debugger.
    ///
    /// Default no-op. The gate calls this once per proxied request; hosts with
    /// the debugger enabled ingest it into the PDB correlation engine. This is
    /// how proxied traffic reaches PDB now that the data plane is Pingora (which
    /// bypasses the old axum `logging_middleware`).
    fn record_exchange(&self, _exchange: HttpExchange) {}

    /// Whether the host consumes completed HTTP exchanges.
    ///
    /// Defaults to `true` to preserve logging for external implementations
    /// that override [`Self::record_exchange`]. Hosts that can determine at
    /// runtime that logging is disabled should return `false`, allowing the
    /// proxy to skip request/response header materialization entirely.
    fn records_http_exchanges(&self) -> bool {
        true
    }

    /// Called at request time, before the upstream responds. A host that
    /// tracks in-flight requests (`pay gate inference`) returns a log id;
    /// the gate echoes it in [`HttpExchange::log_id`] and in
    /// [`PaymentState::record_exchange_update`] calls. Returning `None`
    /// (the default) also disables the gate's response stream observer for
    /// the request — zero overhead for hosts that don't opt in.
    fn record_request_start(&self, _start: &RequestStart) -> Option<u64> {
        None
    }

    /// Live telemetry for an in-flight request (running token counts, TTFT),
    /// emitted by the gate's response stream observer at most ~1/s. Default
    /// no-op.
    fn record_exchange_update(&self, _log_id: u64, _usage: &InferenceUsage) {}
}

/// A completed HTTP exchange handed to [`PaymentState::record_exchange`].
#[derive(Debug, Clone)]
pub struct HttpExchange {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub ms: u64,
    pub req_headers: Vec<(String, String)>,
    pub res_headers: Vec<(String, String)>,
    pub client_ip: String,
    /// Id returned by [`PaymentState::record_request_start`], echoed back so
    /// the host can close the in-flight record it opened.
    pub log_id: Option<u64>,
    /// Final inference telemetry from the gate's stream observer, when the
    /// host opted in via `record_request_start`.
    pub usage: Option<InferenceUsage>,
    /// Pricing/settlement outcome for this exchange, when the endpoint is
    /// metered. `None` for endpoints the gate never prices at all (control
    /// plane, unmetered subscription auth) — distinct from
    /// [`ChargeStatus::NotCharged`], which means a metered endpoint's request
    /// specifically wasn't charged (free tier, short-circuited before
    /// payment).
    pub charge: Option<ChargeOutcome>,
}

/// Outcome of a proxied request's pricing, independent of on-chain
/// settlement timing — a request can be reportable (unit, quantity, USD
/// amount known) before its payment is confirmed on-chain. Covers every
/// [`pay_types::metering::Scheme`]: charge-style schemes (`mpp/charge`,
/// `x402/exact`, `x402/batch`) know this synchronously before forwarding;
/// usage-metered schemes (`x402/upto`, `mpp/session`) only know it once the
/// response has been served and settlement computed.
#[derive(Debug, Clone)]
pub struct ChargeOutcome {
    pub scheme: pay_types::metering::Scheme,
    pub status: ChargeStatus,
    /// `None` iff `status` is [`ChargeStatus::NotCharged`].
    pub currency: Option<String>,
    /// `None` iff `status` is [`ChargeStatus::NotCharged`].
    pub amount_usd: Option<f64>,
    /// The billing dimension that priced this request (e.g. `"tokens"`,
    /// `"requests"`, `"bytes"`) — the serialized form of
    /// [`pay_types::metering::BillingUnit`], mirroring
    /// [`pay_types::metering::ResolvedDimension::unit`]. `None` when the
    /// endpoint's `paywall.yml` doesn't resolve one for this request.
    pub unit: Option<String>,
    /// Quantity billed in `unit`, when the gate computed an exact count
    /// (e.g. a usage-metered token/byte count). `None` for flat per-call
    /// pricing, where quantity is implicitly 1 request.
    pub quantity: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeStatus {
    /// Served and settled for a non-zero amount (on-chain confirmation may
    /// still be pending for deferred schemes).
    Charged,
    /// Served, but settled to zero — a refund (failed delivery, missing-usage
    /// policy, or a `!served_ok` post-response settlement).
    Refunded,
    /// Not charged at all: free tier, or short-circuited before any payment
    /// was verified.
    NotCharged,
    /// The resource was served, but the settlement attempt itself errored
    /// (e.g. a deferred on-chain settle broadcast failed) — distinct from a
    /// deliberate `Refunded`. The amount, if any, is unknown.
    Failed,
}

/// Request-side facts handed to [`PaymentState::record_request_start`].
#[derive(Debug, Clone)]
pub struct RequestStart {
    pub method: String,
    pub path: String,
    /// `Host` header — how the host maps the request to an API/provider.
    pub host: Option<String>,
    pub client_ip: String,
    /// The request carries a payment credential — MPP `Authorization:
    /// Payment`, x402 `PAYMENT-SIGNATURE`, or x402 v1 `X-PAYMENT`. Lets the
    /// host merge the challenge and its retry into one tracked exchange.
    pub payment: bool,
}

/// Inference telemetry accumulated by the gate's response stream observer
/// (OpenAI-compatible SSE, Ollama-native NDJSON, or plain JSON bodies).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InferenceUsage {
    /// Model name reported by the upstream response.
    pub model: Option<String>,
    /// Response was a stream (`text/event-stream` / `application/x-ndjson`).
    pub streamed: bool,
    /// Time to first response body byte, from request receipt.
    pub ttft_ms: Option<u64>,
    pub tokens_prompt: Option<u64>,
    /// Authoritative when the upstream reported usage; otherwise approximated
    /// live from stream events and overwritten if a final count arrives.
    pub tokens_completion: Option<u64>,
    pub tokens_per_sec: Option<f64>,
}

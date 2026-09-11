//! Integration test for the `report-billing-events` binary — runs the
//! actual compiled binary as a subprocess against a real, ephemeral local
//! Redis instance. No mocks: this exercises the exact artifact that gets
//! deployed.
//!
//! Requires `redis-server` on `PATH`. Skips (rather than failing) when it
//! isn't found, so this doesn't break environments without it installed.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

const STREAM_KEY: &str = "pay:billing:events";
const CONSUMER_GROUP: &str = "report-billing-events";

struct RedisServer {
    child: Child,
    port: u16,
}

impl RedisServer {
    fn start() -> Option<Self> {
        if Command::new("redis-server").arg("--version").output().is_err() {
            return None;
        }
        let port = ephemeral_port();
        let child = Command::new("redis-server")
            .args([
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--daemonize",
                "no",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let server = Self { child, port };
        server.wait_ready();
        Some(server)
    }

    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}", self.port)
    }

    fn wait_ready(&self) {
        let client = redis::Client::open(self.url()).expect("valid redis url");
        for _ in 0..50 {
            if client.get_connection().is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("redis-server on port {} did not become ready in time", self.port);
    }
}

impl Drop for RedisServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Bind an ephemeral port and release it immediately. A real TOCTOU race
/// window exists, but is negligible for a local, single-process test suite.
fn ephemeral_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

#[test]
fn report_billing_events_drains_and_acks_a_real_event() {
    let Some(redis_server) = RedisServer::start() else {
        eprintln!("skipping report_billing_events_drains_and_acks_a_real_event: redis-server not found on PATH");
        return;
    };

    let client = redis::Client::open(redis_server.url()).expect("valid redis url");
    let mut conn = client.get_connection().expect("connect to ephemeral redis");

    // Seed the stream exactly as the CLI producer would — one JSON `event`
    // field per entry, matching `pay_core::BillingEvent`'s wire shape.
    let payload = serde_json::json!({
        "method": "POST",
        "path": "v1/simple/echo",
        "status": 200,
        "ms": 42,
        "scheme": "mpp-charge",
        "charge_status": "charged",
        "currency": "SOL",
        "amount_usd": 0.01,
        "unit": "requests",
        "quantity": null,
    })
    .to_string();
    let _: String = redis::cmd("XADD")
        .arg(STREAM_KEY)
        .arg("*")
        .arg("event")
        .arg(&payload)
        .query(&mut conn)
        .expect("seed the stream");

    let bin = env!("CARGO_BIN_EXE_report-billing-events");
    let status = Command::new(bin)
        .env("PAY_BILLING_REDIS_URL", redis_server.url())
        .env("RUN_ONCE", "true")
        .status()
        .expect("run report-billing-events");
    assert!(
        status.success(),
        "report-billing-events exited with {status}"
    );

    // The entry was acknowledged: no pending entries remain for the group.
    // XPENDING's summary reply is `[count, min_id, max_id, consumers]`.
    let pending: redis::Value = redis::cmd("XPENDING")
        .arg(STREAM_KEY)
        .arg(CONSUMER_GROUP)
        .query(&mut conn)
        .expect("XPENDING summary");
    let redis::Value::Array(fields) = &pending else {
        panic!("unexpected XPENDING reply shape: {pending:?}");
    };
    assert_eq!(
        fields[0],
        redis::Value::Int(0),
        "expected every delivered entry to be acknowledged, got {pending:?}"
    );
}

#[test]
fn report_billing_events_requires_the_redis_url() {
    let Some(redis_server) = RedisServer::start() else {
        eprintln!("skipping report_billing_events_requires_the_redis_url: redis-server not found on PATH");
        return;
    };
    // The server only needs to exist so this test doesn't accidentally pass
    // for an unrelated reason; PAY_BILLING_REDIS_URL is deliberately unset.
    drop(redis_server);

    let bin = env!("CARGO_BIN_EXE_report-billing-events");
    let status = Command::new(bin)
        .env_remove("PAY_BILLING_REDIS_URL")
        .status()
        .expect("run report-billing-events");
    assert!(
        !status.success(),
        "expected a config error without PAY_BILLING_REDIS_URL, got {status}"
    );
}

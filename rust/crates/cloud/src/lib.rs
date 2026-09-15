//! pay-cloud v0 — browser onboarding for the `pay` CLI.
//!
//! Serves the embedded onboarding page (`web-ui/dist-cloud`, compiled in via
//! `include_dir!`) and two JSON endpoints:
//!
//! - `POST /api/onboard/start` — page → server: open a session; with a
//!   `provider`, returns that provider's consent URL.
//! - `POST /api/onboard/{provider}/complete` — page → server: the consent
//!   fragment; the driver provisions a wallet onto the session.
//! - `POST /v1/onboard/exchange` — CLI → server: redeem the code with PKCE
//!   and receive the wallet's credentials, once.
//!
//! State is in-memory; sessions expire after [`onboard::SESSION_TTL`].
//! Wallet drivers live in [`drivers`], each behind a cargo feature.

pub mod drivers;
pub mod onboard;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{Response, StatusCode};
use axum::routing::{get, post};
use include_dir::{Dir, include_dir};
use mime_guess::from_path;
use serde_json::json;

pub use onboard::{OnboardSession, SESSION_TTL};

static ASSETS: Dir<'_> = include_dir!("$OUT_DIR/cloud-dist");

/// Shared server state: pending sessions keyed by `sha256(code)` hex, an
/// index from CLI `state` to that key (the consent page echoes `state`),
/// the compiled-in wallet drivers, and the public base URL consent pages
/// redirect back to.
#[derive(Clone)]
pub struct AppState {
    sessions: Arc<Mutex<HashMap<String, OnboardSession>>>,
    by_state: Arc<Mutex<HashMap<String, String>>>,
    drivers: Arc<Vec<Box<dyn drivers::WalletDriver>>>,
    public_url: String,
}

impl AppState {
    /// State with every compiled-in driver. `public_url` is how browsers
    /// reach this server, e.g. `https://cloud.pay.sh` or
    /// `http://127.0.0.1:8402`.
    pub fn new(public_url: impl Into<String>) -> Self {
        Self::with_drivers(public_url, drivers::all())
    }

    /// State with an explicit driver set (tests inject a fake).
    pub fn with_drivers(
        public_url: impl Into<String>,
        drivers: Vec<Box<dyn drivers::WalletDriver>>,
    ) -> Self {
        Self {
            sessions: Arc::default(),
            by_state: Arc::default(),
            drivers: Arc::new(drivers),
            public_url: public_url.into().trim_end_matches('/').to_string(),
        }
    }

    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    /// Where a provider's consent page should send the browser back.
    pub fn consent_redirect_uri(&self, provider_id: &str) -> String {
        format!("{}/onboard/{provider_id}/callback", self.public_url)
    }

    pub fn driver(&self, id: &str) -> Option<&dyn drivers::WalletDriver> {
        self.drivers
            .iter()
            .find(|d| d.id() == id)
            .map(|d| d.as_ref())
    }

    pub fn driver_ids(&self) -> Vec<&'static str> {
        self.drivers.iter().map(|d| d.id()).collect()
    }

    /// Store a session, purging expired ones first.
    pub fn insert_session(&self, session: OnboardSession) {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        let mut by_state = self.by_state.lock().unwrap();
        sessions.retain(|_, s| !s.is_expired_at(now));
        by_state.retain(|_, key| sessions.contains_key(key));
        by_state.insert(session.state.clone(), session.key());
        sessions.insert(session.key(), session);
    }

    /// Remove and return the session for `code`. `None` when unknown or
    /// expired (an expired hit is dropped too).
    pub fn take_session(&self, code: &str) -> Option<OnboardSession> {
        let key = onboard::sha256_hex(code);
        let session = self.sessions.lock().unwrap().remove(&key)?;
        self.by_state.lock().unwrap().remove(&session.state);
        (!session.is_expired_at(Instant::now())).then_some(session)
    }

    /// A live session by its CLI `state`, cloned.
    pub fn session_by_state(&self, state: &str) -> Option<OnboardSession> {
        let key = self.by_state.lock().unwrap().get(state)?.clone();
        let session = self.sessions.lock().unwrap().get(&key)?.clone();
        (!session.is_expired_at(Instant::now())).then_some(session)
    }

    /// Park a provisioned wallet on the session for `state`. False when the
    /// session is gone.
    pub fn attach_wallet(&self, state: &str, wallet: drivers::ProvisionedWallet) -> bool {
        let Some(key) = self.by_state.lock().unwrap().get(state).cloned() else {
            return false;
        };
        match self.sessions.lock().unwrap().get_mut(&key) {
            Some(session) => {
                session.wallet = Some(wallet);
                true
            }
            None => false,
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

/// Full pay-cloud router: health, onboarding JSON endpoints, embedded SPA.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/onboard/start", post(onboard::start))
        .route("/api/onboard/{provider}/complete", post(onboard::complete))
        .route("/v1/onboard/exchange", post(onboard::exchange))
        .route("/", get(serve_index))
        .route("/onboard", get(serve_index))
        .route("/onboard/{*rest}", get(serve_index))
        .fallback(get(serve_static))
        .with_state(state)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(json!({ "status": "ok" }))
}

fn html_response(status: StatusCode, body: &[u8]) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-cache")
        .body(Body::from(body.to_vec()))
        .unwrap()
}

fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .unwrap()
}

/// Serve the SPA entry point (`/`, `/onboard`, `/onboard/*`).
async fn serve_index() -> Response<Body> {
    match ASSETS.get_file("index.html") {
        Some(file) => html_response(StatusCode::OK, file.contents()),
        None => not_found(),
    }
}

/// Serve embedded static files with SPA fallback to `index.html`.
async fn serve_static(req: Request) -> Response<Body> {
    let path = req.uri().path().trim_start_matches('/');

    let file = if path.is_empty() {
        ASSETS.get_file("index.html")
    } else {
        ASSETS
            .get_file(path)
            .or_else(|| ASSETS.get_file(format!("{path}.html")))
            .or_else(|| ASSETS.get_file(format!("{path}/index.html")))
            .or_else(|| ASSETS.get_file("index.html"))
    };

    match file {
        Some(file) => {
            let mime = from_path(file.path()).first_or_octet_stream();
            let cache = if mime.type_() == mime_guess::mime::TEXT
                && mime.subtype() == mime_guess::mime::HTML
            {
                "no-cache"
            } else {
                "public, max-age=31536000, immutable"
            };
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", mime.as_ref())
                .header("Cache-Control", cache)
                .body(Body::from(file.contents().to_vec()))
                .unwrap()
        }
        None => not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::{Method, header};
    use serde_json::Value;
    use tower::ServiceExt;

    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const STATE: &str = "abcdefghijklmnopqrstuvwxyz012345";
    const CALLBACK: &str = "http://127.0.0.1:53211/callback";
    const PUBLIC_URL: &str = "https://cloud.test";

    /// A driver that hands back a fixed wallet, or fails when the api key is
    /// `sk_fail`.
    struct FakeDriver;

    #[async_trait::async_trait]
    impl drivers::WalletDriver for FakeDriver {
        fn id(&self) -> &'static str {
            "fake"
        }
        fn display_name(&self) -> &'static str {
            "Fake custody"
        }
        fn consent_url(&self, redirect_uri: &str, state: &str) -> String {
            format!("https://fake.test/consent?redirect_uri={redirect_uri}&state={state}")
        }
        fn parse_grant(
            &self,
            fragment: &str,
        ) -> Result<(drivers::ConsentGrant, String), drivers::DriverError> {
            let mut grant = drivers::ConsentGrant::default();
            let mut state = None;
            for (k, v) in url::form_urlencoded::parse(fragment.trim_start_matches('#').as_bytes()) {
                match k.as_ref() {
                    "api_key" => grant.api_key = v.into_owned(),
                    "state" => state = Some(v.into_owned()),
                    _ => {}
                }
            }
            let state =
                state.ok_or_else(|| drivers::DriverError::InvalidGrant("no state".into()))?;
            Ok((grant, state))
        }
        async fn provision(
            &self,
            grant: &drivers::ConsentGrant,
        ) -> Result<drivers::ProvisionedWallet, drivers::DriverError> {
            if grant.api_key == "sk_fail" {
                return Err(drivers::DriverError::Rejected {
                    provider: "fake",
                    status: 401,
                    message: "bad key".into(),
                });
            }
            let mut credentials = std::collections::BTreeMap::new();
            credentials.insert("secret_key".to_string(), grant.api_key.clone());
            credentials.insert("wallet_secret".to_string(), "ws-b64".to_string());
            Ok(drivers::ProvisionedWallet {
                provider: "fake",
                credentials,
                wallet_id: "acc_fake".into(),
                address: "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS".into(),
                project_id: Some("pro_1".into()),
            })
        }
    }

    fn test_state() -> AppState {
        AppState::with_drivers(PUBLIC_URL, vec![Box::new(FakeDriver)])
    }

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        let body = match body {
            Some(json) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&json).unwrap())
            }
            None => Body::empty(),
        };
        let res = app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    fn start_body() -> Value {
        json!({
            "email": "a@b.co",
            "callback": CALLBACK,
            "state": STATE,
            "code_challenge": RFC_CHALLENGE,
            "account": "default",
            "host": "test-host",
            "cli": "0.0.0",
        })
    }

    #[tokio::test]
    async fn health_ok() {
        let app = router(test_state());
        let (status, body) = call(&app, Method::GET, "/health", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({ "status": "ok" }));
    }

    #[tokio::test]
    async fn start_then_exchange_end_to_end() {
        let state = test_state();
        let app = router(state.clone());

        let (status, body) =
            call(&app, Method::POST, "/api/onboard/start", Some(start_body())).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let redirect = body["redirect"].as_str().expect("redirect");
        let url = url::Url::parse(redirect).unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(53211));
        assert_eq!(url.path(), "/callback");
        let pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs["state"], STATE);
        let code = pairs["code"].clone();
        assert_eq!(code.len(), 43);
        assert!(onboard::is_base64url_alphabet(&code));
        assert_eq!(state.session_count(), 1);

        // Wrong verifier burns the code.
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/onboard/exchange",
            Some(json!({ "code": code, "code_verifier": "not-the-verifier" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        assert_eq!(state.session_count(), 0);

        // Fresh start, correct verifier.
        let (_, body) = call(&app, Method::POST, "/api/onboard/start", Some(start_body())).await;
        let url = url::Url::parse(body["redirect"].as_str().unwrap()).unwrap();
        let code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/onboard/exchange",
            Some(json!({ "code": code, "code_verifier": RFC_VERIFIER })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            json!({
                "provider": "pay-cloud",
                "status": "pending",
                "email": "a@b.co",
                "network": "mainnet",
                "message": "Wallet provisioning is not available yet.",
            })
        );

        // Single use.
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/onboard/exchange",
            Some(json!({ "code": code, "code_verifier": RFC_VERIFIER })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn provider_flow_start_complete_exchange_hands_over_credentials() {
        let state = test_state();
        let app = router(state.clone());

        // start with a provider → consent URL pointing back at our callback
        let mut body = start_body();
        body.as_object_mut().unwrap().remove("email");
        body["provider"] = json!("fake");
        let (status, res) = call(&app, Method::POST, "/api/onboard/start", Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{res}");
        assert_eq!(res["provider"], "fake");
        assert!(res.get("redirect").is_none());
        let consent = res["consent"].as_str().unwrap();
        assert!(
            consent.contains(&format!("redirect_uri={PUBLIC_URL}/onboard/fake/callback")),
            "{consent}"
        );
        assert!(consent.contains(&format!("state={STATE}")));

        // unknown provider is refused
        let mut bad = start_body();
        bad["provider"] = json!("nope");
        let (status, res) = call(&app, Method::POST, "/api/onboard/start", Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(res["error"], "unknown_provider");

        // complete with a fragment for an unknown state → unknown_session
        let (status, res) = call(
            &app,
            Method::POST,
            "/api/onboard/fake/complete",
            Some(json!({ "fragment": "#api_key=sk_ok&state=notastate1234567" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{res}");
        assert_eq!(res["error"], "unknown_session");

        // provider failure surfaces as 502 and leaves the session usable
        let (status, res) = call(
            &app,
            Method::POST,
            "/api/onboard/fake/complete",
            Some(json!({ "fragment": format!("#api_key=sk_fail&state={STATE}") })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{res}");
        assert_eq!(res["error"], "provider_rejected");

        // complete for real → redirect to the CLI with the code
        let (status, res) = call(
            &app,
            Method::POST,
            "/api/onboard/fake/complete",
            Some(json!({ "fragment": format!("#api_key=sk_ok&state={STATE}") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{res}");
        assert_eq!(res["provider"], "fake");
        assert_eq!(
            res["address"],
            "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS"
        );
        let url = url::Url::parse(res["redirect"].as_str().unwrap()).unwrap();
        assert_eq!(url.path(), "/callback");
        let code = url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .unwrap();

        // second completion is refused
        let (status, res) = call(
            &app,
            Method::POST,
            "/api/onboard/fake/complete",
            Some(json!({ "fragment": format!("#api_key=sk_ok&state={STATE}") })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{res}");
        assert_eq!(res["error"], "already_completed");

        // exchange → ready result with the credentials, once
        let (status, res) = call(
            &app,
            Method::POST,
            "/v1/onboard/exchange",
            Some(json!({ "code": code, "code_verifier": RFC_VERIFIER })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{res}");
        assert_eq!(
            res,
            json!({
                "provider": "fake",
                "status": "ready",
                "network": "mainnet",
                "wallet_id": "acc_fake",
                "pubkey": "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS",
                "project_id": "pro_1",
                "credentials": { "secret_key": "sk_ok", "wallet_secret": "ws-b64" },
            })
        );
        assert_eq!(state.session_count(), 0);
        assert!(state.session_by_state(STATE).is_none());
    }

    #[tokio::test]
    async fn start_rejects_invalid_input_with_json_errors() {
        let app = router(test_state());

        let mut bad_callback = start_body();
        bad_callback["callback"] = json!("https://evil.example/callback");
        let (status, body) =
            call(&app, Method::POST, "/api/onboard/start", Some(bad_callback)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_callback");
        assert!(body["message"].is_string());

        let mut bad_email = start_body();
        bad_email["email"] = json!("nope");
        let (status, body) = call(&app, Method::POST, "/api/onboard/start", Some(bad_email)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_email");

        let mut short_state = start_body();
        short_state["state"] = json!("short");
        let (_, body) = call(&app, Method::POST, "/api/onboard/start", Some(short_state)).await;
        assert_eq!(body["error"], "invalid_state");

        let mut short_challenge = start_body();
        short_challenge["code_challenge"] = json!("short");
        let (_, body) = call(
            &app,
            Method::POST,
            "/api/onboard/start",
            Some(short_challenge),
        )
        .await;
        assert_eq!(body["error"], "invalid_code_challenge");

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/onboard/start")
                    .body(Body::from("not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn exchange_unknown_code_is_invalid_grant() {
        let app = router(test_state());
        let (status, body) = call(
            &app,
            Method::POST,
            "/v1/onboard/exchange",
            Some(json!({ "code": "nope", "code_verifier": RFC_VERIFIER })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn spa_routes_serve_index_html() {
        let app = router(test_state());
        for path in [
            "/",
            "/onboard",
            "/onboard/anything?x=1",
            "/some/unknown/route",
        ] {
            let res = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            let ct = res.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .to_string();
            assert!(ct.starts_with("text/html"), "{path}: {ct}");
        }
    }
}

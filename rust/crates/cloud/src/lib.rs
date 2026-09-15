//! pay-cloud v0 — browser onboarding for the `pay` CLI.
//!
//! Serves the embedded onboarding page (`web-ui/dist-cloud`, compiled in via
//! `include_dir!`) and two JSON endpoints:
//!
//! - `POST /api/onboard/start`   — page → server: mint a one-time code.
//! - `POST /v1/onboard/exchange` — CLI → server: redeem the code with PKCE.
//!
//! No wallet provisioning yet: the exchange returns a `pending` stub. State
//! is in-memory; sessions expire after [`onboard::SESSION_TTL`].

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

/// Shared server state: pending sessions keyed by `sha256(code)` hex.
#[derive(Clone, Default)]
pub struct AppState {
    sessions: Arc<Mutex<HashMap<String, OnboardSession>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a session, purging expired ones first.
    pub fn insert_session(&self, session: OnboardSession) {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| !s.is_expired_at(now));
        sessions.insert(session.key(), session);
    }

    /// Remove and return the session for `code`. `None` when unknown or
    /// expired (an expired hit is dropped too).
    pub fn take_session(&self, code: &str) -> Option<OnboardSession> {
        let key = onboard::sha256_hex(code);
        let session = self.sessions.lock().unwrap().remove(&key)?;
        (!session.is_expired_at(Instant::now())).then_some(session)
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
        let app = router(AppState::new());
        let (status, body) = call(&app, Method::GET, "/health", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({ "status": "ok" }));
    }

    #[tokio::test]
    async fn start_then_exchange_end_to_end() {
        let state = AppState::new();
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
    async fn start_rejects_invalid_input_with_json_errors() {
        let app = router(AppState::new());

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
        let app = router(AppState::new());
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
        let app = router(AppState::new());
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

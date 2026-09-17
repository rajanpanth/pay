//! `/mcp`: the pay tools over MCP streamable HTTP, behind a bearer token.
//!
//! This is the hosted connector's front door. An MCP host (Grok, Claude,
//! ChatGPT, Cursor) is pointed at `https://cloud.pay.sh/mcp` and gets the
//! same tools `pay mcp` serves on stdio, with the request authenticated per
//! call: an OAuth access token from [`crate::oauth`], or one of the static
//! tokens in `PAY_CLOUD_MCP_TOKENS` for hosts that only take a header. A
//! refusal is a 401 with the RFC 9728 `WWW-Authenticate` pointer that
//! starts the OAuth discovery.
//!
//! Every accepted request carries a [`Tenant`] in its extensions;
//! [`crate::tenants::CloudContext`] turns it into the wallet and policy the
//! tools act with.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use sha2::{Digest, Sha256};

/// `1` mounts the connector and its OAuth server.
pub const ENABLE_ENV: &str = "PAY_CLOUD_MCP";
/// Optional comma-separated static bearer tokens.
pub const TOKENS_ENV: &str = "PAY_CLOUD_MCP_TOKENS";
pub const ALLOWED_HOSTS_ENV: &str = "PAY_CLOUD_MCP_ALLOWED_HOSTS";
pub const PATH: &str = "/mcp";

/// Who a request acts for. Today the fingerprint of the static token that
/// authenticated it; the tenant store will map tokens to real tenants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: String,
}

/// Connector configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL browsers and hosts reach this server at; the protected
    /// resource metadata pointer is derived from it.
    pub public_url: String,
    /// `Host` values the transport accepts, guarding against DNS rebinding.
    pub allowed_hosts: Vec<String>,
    /// Static bearer tokens. Empty means every request is refused.
    tokens: Vec<String>,
}

impl Config {
    pub fn new(public_url: &str, tokens: Vec<String>) -> Self {
        let public_url = public_url.trim_end_matches('/').to_string();
        let mut allowed_hosts = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        if let Some((host, port)) = url::Url::parse(&public_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| (h.to_string(), u.port())))
        {
            if !allowed_hosts.contains(&host) {
                allowed_hosts.push(host.clone());
            }
            if let Some(port) = port {
                allowed_hosts.push(format!("{host}:{port}"));
            }
        }
        Self {
            public_url,
            allowed_hosts,
            tokens: tokens.into_iter().filter(|t| !t.is_empty()).collect(),
        }
    }

    /// `None` unless `PAY_CLOUD_MCP` is on: the endpoint is not mounted.
    /// `PAY_CLOUD_MCP_TOKENS` adds comma-separated static tokens;
    /// `PAY_CLOUD_MCP_ALLOWED_HOSTS` (comma-separated) replaces the hosts
    /// derived from the public URL.
    pub fn from_env(public_url: &str) -> Option<Self> {
        let enabled = std::env::var(ENABLE_ENV)
            .ok()
            .is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"));
        if !enabled {
            return None;
        }
        let tokens: Vec<String> = std::env::var(TOKENS_ENV)
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let mut cfg = Self::new(public_url, tokens);
        if let Ok(hosts) = std::env::var(ALLOWED_HOSTS_ENV) {
            let hosts: Vec<String> = hosts
                .split(',')
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .collect();
            if !hosts.is_empty() {
                cfg.allowed_hosts = hosts;
            }
        }
        Some(cfg)
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// RFC 9728 pointer sent on every 401.
    pub fn resource_metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource", self.public_url)
    }

    /// The tenant a static bearer token stands for, if it is one of ours.
    fn authenticate_static(&self, bearer: &str) -> Option<Tenant> {
        self.tokens
            .iter()
            .find(|t| constant_time_eq(t.as_bytes(), bearer.as_bytes()))
            .map(|t| Tenant {
                id: token_fingerprint(t),
            })
    }
}

/// What the bearer middleware checks against: static tokens, and OAuth
/// access tokens when the authorization server is mounted.
#[derive(Clone)]
pub struct Auth {
    pub cfg: Arc<Config>,
    pub oauth: Option<Arc<crate::oauth::Store>>,
}

impl Auth {
    fn authenticate(&self, bearer: &str) -> Option<Tenant> {
        self.oauth
            .as_ref()
            .and_then(|store| store.authenticate(bearer))
            .or_else(|| self.cfg.authenticate_static(bearer))
    }
}

/// Stable, non-reversible id for a token: first 16 hex chars of its SHA-256.
/// A static token's tenant is bound under this id.
pub fn token_fingerprint(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("tok_{}", &hex[..16])
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Routes for the connector: `/mcp` and everything under it. Each session
/// gets a `PayMcp` resolving its calls through `context`.
pub fn router(auth: Auth, context: Arc<dyn pay_mcp::PayContext>) -> Router {
    let transport =
        StreamableHttpServerConfig::default().with_allowed_hosts(auth.cfg.allowed_hosts.clone());
    let service: StreamableHttpService<pay_mcp::PayMcp, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(pay_mcp::PayMcp::with_context(context.clone())),
            Default::default(),
            transport,
        );
    Router::new()
        .nest_service(PATH, service)
        .layer(middleware::from_fn_with_state(auth, require_bearer))
}

/// Refuse anything without a live token; tag the rest with its tenant.
async fn require_bearer(State(auth): State<Auth>, mut req: Request, next: Next) -> Response {
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    match bearer.and_then(|b| auth.authenticate(b)) {
        Some(tenant) => {
            req.extensions_mut().insert(tenant);
            next.run(req).await
        }
        None => unauthorized(&auth.cfg),
    }
}

fn unauthorized(cfg: &Config) -> Response {
    let challenge = format!(
        "Bearer resource_metadata=\"{}\", error=\"invalid_token\"",
        cfg.resource_metadata_url()
    );
    let body = serde_json::json!({
        "error": "unauthorized",
        "message": "A bearer token for cloud.pay.sh is required.",
    });
    let mut response = (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge).expect("ascii challenge"),
    );
    response
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Method;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    pub(crate) const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
    pub(crate) const INITIALIZED: &str =
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    const TOOLS_LIST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;

    fn app() -> Router {
        app_with_tenants(Arc::default())
    }

    pub(crate) fn app_with_tenants(tenants: Arc<crate::tenants::TenantRegistry>) -> Router {
        router(
            Auth {
                cfg: Arc::new(Config::new(
                    "https://cloud.test",
                    vec!["tok-alpha".to_string(), "tok-beta".to_string()],
                )),
                oauth: None,
            },
            Arc::new(crate::tenants::CloudContext::new(tenants)),
        )
    }

    pub(crate) async fn mcp_post(
        app: &Router,
        bearer: Option<&str>,
        session: Option<&str>,
        body: &str,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        mcp_post_inner(app, bearer, session, body).await
    }

    async fn mcp_post_inner(
        app: &Router,
        bearer: Option<&str>,
        session: Option<&str>,
        body: &str,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::HOST, "cloud.test")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(bearer) = bearer {
            req = req.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        if let Some(session) = session {
            req = req.header("mcp-session-id", session);
        }
        let res = app
            .clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    /// The JSON payloads of an SSE body.
    pub(crate) fn sse_json(body: &str) -> Vec<Value> {
        body.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .filter_map(|d| serde_json::from_str(d.trim()).ok())
            .collect()
    }

    #[test]
    fn config_derives_allowed_hosts_from_the_public_url() {
        let cfg = Config::new("https://cloud.pay.sh/", vec!["t".into(), "".into()]);
        assert_eq!(cfg.public_url, "https://cloud.pay.sh");
        assert!(cfg.allowed_hosts.contains(&"cloud.pay.sh".to_string()));
        assert!(cfg.allowed_hosts.contains(&"127.0.0.1".to_string()));
        assert_eq!(cfg.token_count(), 1, "empty tokens are dropped");
        assert_eq!(
            cfg.resource_metadata_url(),
            "https://cloud.pay.sh/.well-known/oauth-protected-resource"
        );

        let local = Config::new("http://127.0.0.1:8402", vec![]);
        assert!(local.allowed_hosts.contains(&"127.0.0.1:8402".to_string()));
        assert_eq!(local.token_count(), 0);
    }

    #[test]
    fn tokens_map_to_stable_opaque_tenants() {
        let cfg = Config::new("https://cloud.test", vec!["tok-alpha".into()]);
        let tenant = cfg.authenticate_static("tok-alpha").unwrap();
        assert!(tenant.id.starts_with("tok_"));
        assert_eq!(tenant.id.len(), 20);
        assert!(!tenant.id.contains("alpha"));
        assert_eq!(cfg.authenticate_static("tok-alpha"), Some(tenant));
        assert!(cfg.authenticate_static("tok-alph").is_none());
        assert!(cfg.authenticate_static("").is_none());
    }

    #[tokio::test]
    async fn requests_without_a_valid_token_get_401_with_the_metadata_pointer() {
        let app = app();
        for bearer in [None, Some("nope"), Some("")] {
            let (status, headers, body) = mcp_post(&app, bearer, None, INIT).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
            let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
            assert!(
                challenge.starts_with(
                    "Bearer resource_metadata=\"https://cloud.test/.well-known/oauth-protected-resource\""
                ),
                "{challenge}"
            );
            let json: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["error"], "unauthorized");
        }
    }

    #[tokio::test]
    async fn a_token_opens_a_session_and_lists_the_pay_tools() {
        let app = app();
        let (status, headers, body) = mcp_post(&app, Some("tok-alpha"), None, INIT).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let session = headers["mcp-session-id"].to_str().unwrap().to_string();
        let init = sse_json(&body);
        assert_eq!(
            init[0]["result"]["serverInfo"]["name"],
            json!("pay"),
            "{body}"
        );

        let (status, _, _) = mcp_post(&app, Some("tok-alpha"), Some(&session), INITIALIZED).await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let (status, _, body) = mcp_post(&app, Some("tok-alpha"), Some(&session), TOOLS_LIST).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let tools: Vec<String> = sse_json(&body)[0]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        for expected in [
            "curl",
            "get_balance",
            "topup",
            "list_catalog",
            "search_catalog",
        ] {
            assert!(tools.contains(&expected.to_string()), "{tools:?}");
        }
    }

    #[tokio::test]
    async fn a_foreign_host_header_is_refused_by_the_transport() {
        let app = app();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::HOST, "evil.example")
            .header(header::AUTHORIZATION, "Bearer tok-alpha")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::from(INIT))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert!(
            res.status().is_client_error(),
            "DNS-rebinding hosts must not reach the session: {}",
            res.status()
        );
    }
}

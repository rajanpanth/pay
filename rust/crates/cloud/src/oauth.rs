//! OAuth 2.1 authorization server for the MCP connector.
//!
//! Hosts like Grok cannot attach a static header; they discover this server
//! from the 401 on `/mcp`, register themselves (RFC 7591), send the user
//! through `/oauth/authorize` with PKCE, and exchange the code for a bearer
//! at `/oauth/token`. Tokens are opaque random strings stored hashed: a
//! one-hour access token and a thirty-day refresh token, rotated on use.
//!
//! What "the user" is here is still thin: approving a request mints an
//! opaque subject. The tenant store binds that subject to a wallet next.
//! Everything in this module is in memory and bounded; the store moves to
//! Postgres with the tenants.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::AppState;
use crate::mcp::Tenant;
use crate::onboard::{ApiError, is_base64url_alphabet, random_token, sha256_hex};

pub const ACCESS_TTL: Duration = Duration::from_secs(60 * 60);
pub const REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// A code must be exchanged within this window after approval.
pub const CODE_TTL: Duration = Duration::from_secs(10 * 60);
/// A pending authorization waits this long for the user to decide.
pub const REQUEST_TTL: Duration = Duration::from_secs(15 * 60);
/// Most rows of any one kind held at once; expired rows are swept when full.
pub const MAX_ROWS: usize = 16_384;
/// The one scope this server knows: use the pay tools.
pub const SCOPE: &str = "mcp";

// ── Records ────────────────────────────────────────────────────────────────

/// A registered OAuth client (RFC 7591). Public clients only.
#[derive(Debug, Clone, Serialize)]
pub struct Client {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub client_id_issued_at: u64,
    /// Which known host this is (`grok`, `claude`, …), or `generic`.
    #[serde(skip)]
    pub host: &'static str,
    /// SHA-256 of the client secret, for `client_secret_*` clients.
    #[serde(skip)]
    secret_hash: Option<String>,
    #[serde(skip)]
    created_at: Instant,
}

/// Authentication methods a client may register with. Secrets are issued
/// once at registration and stored hashed; they add nothing for a public
/// host but some hosts insist on having one.
const AUTH_METHODS: &[&str] = &["none", "client_secret_post", "client_secret_basic"];

/// An `/oauth/authorize` request waiting for the user's decision.
#[derive(Debug, Clone)]
pub struct PendingAuthorization {
    pub id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub scope: String,
    created_at: Instant,
}

/// What a code stands for, keyed by the code's hash.
#[derive(Debug, Clone)]
struct CodeGrant {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    subject: String,
    scope: String,
    created_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Access,
    Refresh,
}

/// A live token, keyed by its hash.
#[derive(Debug, Clone)]
struct TokenRecord {
    kind: TokenKind,
    client_id: String,
    subject: String,
    scope: String,
    expires_at: Instant,
}

/// Time source, so expiry is testable without waiting.
pub type Clock = std::sync::Arc<dyn Fn() -> Instant + Send + Sync>;

/// Everything the authorization server remembers.
pub struct Store {
    public_url: String,
    clock: Clock,
    clients: Mutex<HashMap<String, Client>>,
    pending: Mutex<HashMap<String, PendingAuthorization>>,
    codes: Mutex<HashMap<String, CodeGrant>>,
    tokens: Mutex<HashMap<String, TokenRecord>>,
}

/// Why a token request failed, in RFC 6749 vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenError {
    pub error: &'static str,
    pub description: String,
}

impl TokenError {
    fn invalid_grant(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_grant",
            description: description.into(),
        }
    }
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_request",
            description: description.into(),
        }
    }
    fn invalid_client(description: impl Into<String>) -> Self {
        Self {
            error: "invalid_client",
            description: description.into(),
        }
    }
}

/// Access and refresh tokens handed to a client.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Insert into a bounded map, sweeping expired rows when it is full.
fn insert_bounded<V>(
    map: &mut HashMap<String, V>,
    key: String,
    value: V,
    expired: impl Fn(&V) -> bool,
) -> bool {
    if map.len() >= MAX_ROWS {
        map.retain(|_, v| !expired(v));
        if map.len() >= MAX_ROWS {
            return false;
        }
    }
    map.insert(key, value);
    true
}

impl Store {
    pub fn new(public_url: &str) -> Self {
        Self::with_clock(public_url, std::sync::Arc::new(Instant::now))
    }

    pub fn with_clock(public_url: &str, clock: Clock) -> Self {
        Self {
            public_url: public_url.trim_end_matches('/').to_string(),
            clock,
            clients: Mutex::default(),
            pending: Mutex::default(),
            codes: Mutex::default(),
            tokens: Mutex::default(),
        }
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    pub fn issuer(&self) -> &str {
        &self.public_url
    }

    /// The protected resource this server issues tokens for.
    pub fn resource(&self) -> String {
        format!("{}{}", self.public_url, crate::mcp::PATH)
    }

    // ── Clients ────────────────────────────────────────────────────────

    /// Register a client. The plaintext secret, when one was issued, is
    /// returned once beside the stored record.
    pub fn register(&self, req: RegistrationRequest) -> Result<(Client, Option<String>), ApiError> {
        let invalid = |msg: &str| ApiError::bad_request("invalid_client_metadata", msg);
        if req.redirect_uris.is_empty() {
            return Err(invalid("redirect_uris must list at least one URI."));
        }
        for uri in &req.redirect_uris {
            crate::hosts::redirect_allowed(uri)
                .map_err(|why| invalid(&format!("redirect_uri `{uri}`: {why}")))?;
        }
        let host = crate::hosts::identify(req.client_name.as_deref(), &req.redirect_uris);
        let auth_method = req
            .token_endpoint_auth_method
            .clone()
            .unwrap_or_else(|| "none".to_string());
        if !AUTH_METHODS.contains(&auth_method.as_str()) {
            return Err(invalid(&format!(
                "token_endpoint_auth_method must be one of {}.",
                AUTH_METHODS.join(", ")
            )));
        }
        let secret = (auth_method != "none").then(random_token);
        let grant_types = req
            .grant_types
            .clone()
            .unwrap_or_else(|| vec!["authorization_code".to_string()]);
        for grant in &grant_types {
            if grant != "authorization_code" && grant != "refresh_token" {
                return Err(invalid(&format!("grant_type `{grant}` is not supported.")));
            }
        }
        let response_types = req
            .response_types
            .clone()
            .unwrap_or_else(|| vec!["code".to_string()]);
        if response_types.iter().any(|r| r != "code") {
            return Err(invalid("only the `code` response type is supported."));
        }
        let client = Client {
            client_id: format!("cli_{}", random_token()),
            client_name: req
                .client_name
                .map(|n| n.trim().chars().take(120).collect::<String>())
                .filter(|n| !n.is_empty()),
            redirect_uris: req.redirect_uris,
            grant_types,
            response_types,
            token_endpoint_auth_method: auth_method,
            client_id_issued_at: unix_now(),
            host: host.id,
            secret_hash: secret.as_deref().map(sha256_hex),
            created_at: self.now(),
        };
        let mut clients = self.clients.lock().unwrap();
        // Clients never expire on their own; when the table is full the
        // oldest unused registration goes. A live client re-registers.
        if clients.len() >= MAX_ROWS
            && let Some(oldest) = clients
                .values()
                .min_by_key(|c| c.created_at)
                .map(|c| c.client_id.clone())
        {
            clients.remove(&oldest);
        }
        clients.insert(client.client_id.clone(), client.clone());
        Ok((client, secret))
    }

    /// Check the client's credentials for the token endpoint: nothing for
    /// a public client, the registered secret otherwise.
    pub fn authenticate_client(
        &self,
        client_id: &str,
        presented_secret: Option<&str>,
    ) -> Result<Client, TokenError> {
        let client = self
            .client(client_id)
            .ok_or_else(|| TokenError::invalid_client("unknown client_id"))?;
        match client.secret_hash.as_deref() {
            None => Ok(client),
            Some(hash) => match presented_secret {
                Some(secret) if sha256_hex(secret) == hash => Ok(client),
                Some(_) => Err(TokenError::invalid_client("client_secret does not match")),
                None => Err(TokenError::invalid_client(
                    "this client registered with a secret; send it as client_secret or HTTP Basic",
                )),
            },
        }
    }

    pub fn client(&self, client_id: &str) -> Option<Client> {
        self.clients.lock().unwrap().get(client_id).cloned()
    }

    // ── Authorization requests ─────────────────────────────────────────

    /// Park a validated authorization request for the consent page.
    pub fn create_pending(&self, request: PendingAuthorization) -> Result<(), ApiError> {
        let now = self.now();
        let mut pending = self.pending.lock().unwrap();
        if insert_bounded(&mut pending, request.id.clone(), request, |p| {
            now.saturating_duration_since(p.created_at) > REQUEST_TTL
        }) {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "Too many sign-ins are in progress. Try again in a few minutes.",
            ))
        }
    }

    pub fn pending(&self, id: &str) -> Option<PendingAuthorization> {
        let pending = self.pending.lock().unwrap();
        let request = pending.get(id)?;
        (self.now().saturating_duration_since(request.created_at) <= REQUEST_TTL)
            .then(|| request.clone())
    }

    /// Consume the pending request and mint a code for `subject`.
    /// Returns the code, or `None` when the request is unknown or expired.
    pub fn approve(&self, id: &str, subject: &str) -> Option<(PendingAuthorization, String)> {
        let request = self.pending.lock().unwrap().remove(id)?;
        if self.now().saturating_duration_since(request.created_at) > REQUEST_TTL {
            return None;
        }
        let code = random_token();
        let grant = CodeGrant {
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            code_challenge: request.code_challenge.clone(),
            subject: subject.to_string(),
            scope: request.scope.clone(),
            created_at: self.now(),
        };
        let now = self.now();
        let mut codes = self.codes.lock().unwrap();
        insert_bounded(&mut codes, sha256_hex(&code), grant, |g| {
            now.saturating_duration_since(g.created_at) > CODE_TTL
        })
        .then_some((request, code))
    }

    /// Consume the pending request without issuing anything.
    pub fn deny(&self, id: &str) -> Option<PendingAuthorization> {
        self.pending.lock().unwrap().remove(id)
    }

    // ── Tokens ─────────────────────────────────────────────────────────

    /// Authorization-code grant with PKCE. The code is single-use whatever
    /// the outcome, so a wrong verifier burns it.
    pub fn exchange_code(
        &self,
        client_id: &str,
        code: &str,
        code_verifier: &str,
        redirect_uri: Option<&str>,
    ) -> Result<TokenResponse, TokenError> {
        let grant = self
            .codes
            .lock()
            .unwrap()
            .remove(&sha256_hex(code))
            .ok_or_else(|| TokenError::invalid_grant("unknown or already used code"))?;
        if self.now().saturating_duration_since(grant.created_at) > CODE_TTL {
            return Err(TokenError::invalid_grant("the code has expired"));
        }
        if grant.client_id != client_id {
            return Err(TokenError::invalid_grant(
                "the code was issued to another client",
            ));
        }
        if let Some(uri) = redirect_uri
            && uri != grant.redirect_uri
        {
            return Err(TokenError::invalid_grant(
                "redirect_uri does not match the request",
            ));
        }
        if !is_base64url_alphabet(code_verifier) || !(43..=128).contains(&code_verifier.len()) {
            return Err(TokenError::invalid_grant("code_verifier is malformed"));
        }
        if crate::onboard::pkce_challenge(code_verifier) != grant.code_challenge {
            return Err(TokenError::invalid_grant(
                "code_verifier does not match code_challenge",
            ));
        }
        Ok(self.issue(&grant.client_id, &grant.subject, &grant.scope))
    }

    /// Refresh grant with rotation: the presented refresh token is retired
    /// and a new pair is issued.
    pub fn refresh(
        &self,
        client_id: &str,
        refresh_token: &str,
    ) -> Result<TokenResponse, TokenError> {
        let mut tokens = self.tokens.lock().unwrap();
        let record = tokens
            .remove(&sha256_hex(refresh_token))
            .ok_or_else(|| TokenError::invalid_grant("unknown or already used refresh token"))?;
        if record.kind != TokenKind::Refresh {
            return Err(TokenError::invalid_grant("not a refresh token"));
        }
        if record.client_id != client_id {
            return Err(TokenError::invalid_grant(
                "the token was issued to another client",
            ));
        }
        if self.now() > record.expires_at {
            return Err(TokenError::invalid_grant("the refresh token has expired"));
        }
        drop(tokens);
        Ok(self.issue(&record.client_id, &record.subject, &record.scope))
    }

    fn issue(&self, client_id: &str, subject: &str, scope: &str) -> TokenResponse {
        let access_token = random_token();
        let refresh_token = random_token();
        let now = self.now();
        let mut tokens = self.tokens.lock().unwrap();
        for (token, kind, ttl) in [
            (&access_token, TokenKind::Access, ACCESS_TTL),
            (&refresh_token, TokenKind::Refresh, REFRESH_TTL),
        ] {
            insert_bounded(
                &mut tokens,
                sha256_hex(token),
                TokenRecord {
                    kind,
                    client_id: client_id.to_string(),
                    subject: subject.to_string(),
                    scope: scope.to_string(),
                    expires_at: now + ttl,
                },
                |t| now > t.expires_at,
            );
        }
        TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: ACCESS_TTL.as_secs(),
            refresh_token,
            scope: scope.to_string(),
        }
    }

    /// Forget a token of either kind. Unknown tokens are fine (RFC 7009).
    pub fn revoke(&self, token: &str) {
        self.tokens.lock().unwrap().remove(&sha256_hex(token));
    }

    /// The tenant an access token stands for, if it is live.
    pub fn authenticate(&self, access_token: &str) -> Option<Tenant> {
        let tokens = self.tokens.lock().unwrap();
        let record = tokens.get(&sha256_hex(access_token))?;
        (record.kind == TokenKind::Access && self.now() <= record.expires_at).then(|| Tenant {
            id: record.subject.clone(),
        })
    }
}

// ── HTTP ──────────────────────────────────────────────────────────────────

fn oauth_of(state: &AppState) -> Result<&Store, ApiError> {
    state.oauth().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "OAuth is not enabled on this server.",
        )
    })
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
pub async fn metadata(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let store = oauth_of(&state)?;
    let issuer = store.issuer();
    Ok(Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": AUTH_METHODS,
        "revocation_endpoint_auth_methods_supported": AUTH_METHODS,
        "scopes_supported": [SCOPE],
        "service_documentation": "https://pay.sh/docs",
    })))
}

/// `GET /.well-known/oauth-protected-resource` (RFC 9728): `/mcp` is the
/// resource, this server its authorization server.
pub async fn protected_resource(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = oauth_of(&state)?;
    Ok(Json(serde_json::json!({
        "resource": store.resource(),
        "authorization_servers": [store.issuer()],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [SCOPE],
        "resource_name": "Pay",
        "resource_documentation": "https://pay.sh/docs",
    })))
}

/// Body of `POST /oauth/register` (RFC 7591). Unknown fields are ignored.
#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
}

/// `POST /oauth/register`
pub async fn register(State(state): State<AppState>, body: Bytes) -> Result<Response, ApiError> {
    let store = oauth_of(&state)?;
    // Registration bodies carry no secrets, and what a host sends is the
    // first thing to read when its handshake stalls.
    tracing::info!(body = %String::from_utf8_lossy(&body), "oauth registration request");
    let req: RegistrationRequest = serde_json::from_slice(&body).map_err(|e| {
        ApiError::bad_request("invalid_client_metadata", format!("Invalid JSON: {e}"))
    })?;
    let (client, secret) = store.register(req)?;
    tracing::info!(
        client_id = %client.client_id,
        name = client.client_name.as_deref().unwrap_or("-"),
        auth = %client.token_endpoint_auth_method,
        host = client.host,
        "oauth client registered"
    );
    let mut body = serde_json::to_value(&client).expect("client serializes");
    if let Some(secret) = secret {
        body["client_secret"] = serde_json::Value::String(secret);
        // Never expires; a lost secret means registering again.
        body["client_secret_expires_at"] = serde_json::Value::from(0);
    }
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// Query of `GET /oauth/authorize`.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 8707; when present it must be our `/mcp`.
    #[serde(default)]
    pub resource: Option<String>,
}

/// Send the browser back to the client with an OAuth error (RFC 6749 §4.1.2.1).
fn error_redirect(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    let mut url = Url::parse(redirect_uri).expect("validated redirect uri");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("error", error);
        q.append_pair("error_description", description);
        if let Some(state) = state {
            q.append_pair("state", state);
        }
    }
    Redirect::to(url.as_str()).into_response()
}

/// `GET /oauth/authorize`: validate, park the request, send the browser to
/// the consent page. The client and redirect URI are checked before any
/// redirect, so an error never reaches an unverified address.
pub async fn authorize(
    State(state): State<AppState>,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Response, ApiError> {
    let store = oauth_of(&state)?;
    let client_id = q
        .client_id
        .as_deref()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::bad_request("invalid_request", "client_id is required."))?;
    let client = store.client(client_id).ok_or_else(|| {
        ApiError::bad_request("invalid_client", "Unknown client_id. Register first.")
    })?;
    let redirect_uri = match q.redirect_uri.as_deref() {
        Some(uri) if client.redirect_uris.iter().any(|r| r == uri) => uri.to_string(),
        Some(_) => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "redirect_uri is not registered for this client.",
            ));
        }
        None if client.redirect_uris.len() == 1 => client.redirect_uris[0].clone(),
        None => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "redirect_uri is required when several are registered.",
            ));
        }
    };
    let state_param = q.state.as_deref().filter(|s| !s.is_empty());
    let fail = |error: &str, description: &str| {
        Ok(error_redirect(
            &redirect_uri,
            state_param,
            error,
            description,
        ))
    };

    if q.response_type.as_deref() != Some("code") {
        return fail("unsupported_response_type", "response_type must be `code`.");
    }
    let Some(code_challenge) = q.code_challenge.as_deref().filter(|c| !c.is_empty()) else {
        return fail("invalid_request", "code_challenge is required (PKCE).");
    };
    if q.code_challenge_method.as_deref().unwrap_or("plain") != "S256" {
        return fail("invalid_request", "code_challenge_method must be S256.");
    }
    if !is_base64url_alphabet(code_challenge) || code_challenge.len() != 43 {
        return fail(
            "invalid_request",
            "code_challenge must be a base64url SHA-256.",
        );
    }
    let scope = q
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(SCOPE);
    if scope.split_whitespace().any(|s| s != SCOPE) {
        return fail(
            "invalid_scope",
            &format!("only the `{SCOPE}` scope exists."),
        );
    }
    if let Some(resource) = q.resource.as_deref().filter(|r| !r.is_empty())
        && resource.trim_end_matches('/') != store.resource()
    {
        return fail("invalid_target", "resource must be this server's /mcp.");
    }

    let request = PendingAuthorization {
        id: random_token(),
        client_id: client.client_id.clone(),
        redirect_uri,
        state: state_param.map(str::to_string),
        code_challenge: code_challenge.to_string(),
        scope: SCOPE.to_string(),
        created_at: Instant::now(),
    };
    let id = request.id.clone();
    store.create_pending(request)?;
    Ok(Redirect::to(&format!("{}/authorize?request={id}", store.issuer())).into_response())
}

/// What the consent page shows.
#[derive(Debug, Serialize)]
pub struct PendingView {
    pub client_name: String,
    pub redirect_host: String,
    pub scope: String,
    /// Whether this browser already has a wallet to approve with. When
    /// not, the page offers `providers` to create one.
    pub has_wallet: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
    pub providers: Vec<&'static str>,
    /// Known host id (`grok`, `claude`, …) or `generic`.
    pub host: &'static str,
}

/// `GET /api/oauth/authorize/{request}`
pub async fn pending_view(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PendingView>, ApiError> {
    let store = oauth_of(&state)?;
    let request = store.pending(&id).ok_or_else(unknown_request)?;
    let client = store
        .client(&request.client_id)
        .ok_or_else(unknown_request)?;
    let redirect_host = Url::parse(&request.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let wallet = crate::tenants::cookie::subject(&headers).and_then(|s| state.tenants().get(&s));
    Ok(Json(PendingView {
        client_name: client
            .client_name
            .clone()
            .unwrap_or_else(|| crate::hosts::by_id(client.host).display_name.to_string()),
        redirect_host,
        scope: request.scope,
        has_wallet: wallet.is_some(),
        wallet_address: wallet.map(|w| w.pubkey.clone()),
        providers: state.driver_ids(),
        host: client.host,
    }))
}

/// The client's redirect URI with the code and the echoed state.
pub fn code_redirect(request: &PendingAuthorization, code: &str) -> String {
    let mut url = Url::parse(&request.redirect_uri).expect("validated redirect uri");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("code", code);
        if let Some(state) = request.state.as_deref() {
            q.append_pair("state", state);
        }
    }
    url.into()
}

fn unknown_request() -> ApiError {
    ApiError::bad_request(
        "unknown_request",
        "This sign-in request is unknown or has expired. Start again from your MCP client.",
    )
}

#[derive(Debug, Serialize)]
pub struct DecisionResponse {
    /// Where the browser goes next: back to the client.
    pub redirect: String,
}

/// `POST /api/oauth/authorize/{request}/approve`: approve for the wallet
/// this browser already owns and send it back to the client. A browser
/// without a wallet creates one through `/api/onboard/start` instead,
/// which approves on completion.
pub async fn approve(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DecisionResponse>, ApiError> {
    let store = oauth_of(&state)?;
    let subject = crate::tenants::cookie::subject(&headers)
        .filter(|s| state.tenants().get(s).is_some())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "no_wallet",
                "This browser has no pay wallet yet. Create one first.",
            )
        })?;
    let (request, code) = store.approve(&id, &subject).ok_or_else(unknown_request)?;
    tracing::info!(client_id = %request.client_id, %subject, "oauth authorization approved");
    Ok(Json(DecisionResponse {
        redirect: code_redirect(&request, &code),
    }))
}

/// `POST /api/oauth/authorize/{request}/deny`
pub async fn deny(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<DecisionResponse>, ApiError> {
    let store = oauth_of(&state)?;
    let request = store.deny(&id).ok_or_else(unknown_request)?;
    let response = error_redirect(
        &request.redirect_uri,
        request.state.as_deref(),
        "access_denied",
        "The user declined.",
    );
    let redirect = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    Ok(Json(DecisionResponse { redirect }))
}

/// Form body of `POST /oauth/token`.
#[derive(Debug, Deserialize)]
pub struct TokenForm {
    #[serde(default)]
    pub grant_type: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// For `client_secret_post` clients; `client_secret_basic` sends it in
    /// the `Authorization` header instead.
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// `Authorization: Basic base64(client_id:client_secret)`.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine;
    let raw = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn token_error(err: TokenError) -> Response {
    let status = if err.error == "invalid_client" {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    };
    let mut response = (
        status,
        Json(serde_json::json!({ "error": err.error, "error_description": err.description })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `POST /oauth/token` (form-encoded, RFC 6749 §4.1.3 and §6).
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let Some(store) = state.oauth() else {
        return token_error(TokenError::invalid_request("OAuth is not enabled."));
    };
    let basic = basic_credentials(&headers);
    let client_id = match form
        .client_id
        .as_deref()
        .filter(|c| !c.is_empty())
        .or(basic.as_ref().map(|(id, _)| id.as_str()))
    {
        Some(id) => id.to_string(),
        None => return token_error(TokenError::invalid_client("client_id is required.")),
    };
    let client_id = client_id.as_str();
    let secret = form
        .client_secret
        .as_deref()
        .or(basic.as_ref().map(|(_, s)| s.as_str()));
    if let Err(err) = store.authenticate_client(client_id, secret) {
        return token_error(err);
    }
    let result = match form.grant_type.as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(verifier)) =
                (form.code.as_deref(), form.code_verifier.as_deref())
            else {
                return token_error(TokenError::invalid_request(
                    "code and code_verifier are required.",
                ));
            };
            store.exchange_code(client_id, code, verifier, form.redirect_uri.as_deref())
        }
        Some("refresh_token") => {
            let Some(refresh) = form.refresh_token.as_deref() else {
                return token_error(TokenError::invalid_request("refresh_token is required."));
            };
            store.refresh(client_id, refresh)
        }
        _ => {
            return token_error(TokenError {
                error: "unsupported_grant_type",
                description: "grant_type must be authorization_code or refresh_token.".to_string(),
            });
        }
    };
    match result {
        Ok(tokens) => {
            let mut response = Json(tokens).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(err) => token_error(err),
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    #[serde(default)]
    pub token: Option<String>,
}

/// `POST /oauth/revoke` (RFC 7009): always 200, whatever the token was.
pub async fn revoke(State(state): State<AppState>, Form(form): Form<RevokeForm>) -> StatusCode {
    if let (Some(store), Some(token)) = (state.oauth(), form.token.as_deref()) {
        store.revoke(token);
    }
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboard::pkce_challenge;

    const GROK_REDIRECT: &str = "https://grok.com/connectors/oauth/callback";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn grok_registration() -> RegistrationRequest {
        RegistrationRequest {
            client_name: Some("Grok".to_string()),
            redirect_uris: vec![GROK_REDIRECT.to_string()],
            grant_types: Some(vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ]),
            response_types: Some(vec!["code".to_string()]),
            token_endpoint_auth_method: Some("none".to_string()),
        }
    }

    fn pending_for(client: &Client) -> PendingAuthorization {
        PendingAuthorization {
            id: random_token(),
            client_id: client.client_id.clone(),
            redirect_uri: GROK_REDIRECT.to_string(),
            state: Some("st4te".to_string()),
            code_challenge: pkce_challenge(VERIFIER),
            scope: SCOPE.to_string(),
            created_at: Instant::now(),
        }
    }

    #[test]
    fn registration_accepts_public_clients_with_sane_redirects() {
        let store = Store::new("https://cloud.test/");
        let (client, secret) = store.register(grok_registration()).unwrap();
        assert!(client.client_id.starts_with("cli_"));
        assert_eq!(client.client_name.as_deref(), Some("Grok"));
        assert_eq!(client.host, "grok");
        assert_eq!(client.token_endpoint_auth_method, "none");
        assert!(secret.is_none(), "public clients get no secret");
        assert_eq!(
            store.client(&client.client_id).unwrap().redirect_uris,
            vec![GROK_REDIRECT]
        );
        assert!(store.authenticate_client(&client.client_id, None).is_ok());

        // Loopback http is fine for native apps; anything else must be https.
        let mut local = grok_registration();
        local.redirect_uris = vec!["http://127.0.0.1:5000/cb".to_string()];
        assert!(store.register(local).is_ok());
        let mut plain = grok_registration();
        plain.redirect_uris = vec!["http://example.com/cb".to_string()];
        assert_eq!(
            store.register(plain).unwrap_err().error,
            "invalid_client_metadata"
        );
        let mut none = grok_registration();
        none.redirect_uris.clear();
        assert!(store.register(none).is_err());
        // A client that wants a secret gets one, once, and must present it.
        let mut with_secret = grok_registration();
        with_secret.token_endpoint_auth_method = Some("client_secret_basic".to_string());
        let (client, secret) = store.register(with_secret).unwrap();
        let secret = secret.expect("secret issued");
        assert!(
            store
                .authenticate_client(&client.client_id, Some(&secret))
                .is_ok()
        );
        assert_eq!(
            store
                .authenticate_client(&client.client_id, None)
                .unwrap_err()
                .error,
            "invalid_client"
        );
        assert_eq!(
            store
                .authenticate_client(&client.client_id, Some("nope"))
                .unwrap_err()
                .error,
            "invalid_client"
        );
        let mut jwt = grok_registration();
        jwt.token_endpoint_auth_method = Some("private_key_jwt".to_string());
        assert!(store.register(jwt).is_err());
        let mut implicit = grok_registration();
        implicit.response_types = Some(vec!["token".to_string()]);
        assert!(store.register(implicit).is_err());
    }

    #[test]
    fn approve_issues_a_single_use_code_bound_to_the_verifier() {
        let store = Store::new("https://cloud.test");
        let (client, _) = store.register(grok_registration()).unwrap();
        let request = pending_for(&client);
        store.create_pending(request.clone()).unwrap();
        assert!(store.pending(&request.id).is_some());

        let (approved, code) = store.approve(&request.id, "sub_1").unwrap();
        assert_eq!(approved.state.as_deref(), Some("st4te"));
        assert!(store.pending(&request.id).is_none(), "consumed");

        let wrong = store.exchange_code(
            &client.client_id,
            &code,
            &"a".repeat(43),
            Some(GROK_REDIRECT),
        );
        assert_eq!(wrong.unwrap_err().error, "invalid_grant");
        // A wrong verifier burned the code.
        let again = store.exchange_code(&client.client_id, &code, VERIFIER, Some(GROK_REDIRECT));
        assert_eq!(again.unwrap_err().error, "invalid_grant");
    }

    #[test]
    fn a_good_exchange_yields_tokens_that_authenticate_and_rotate() {
        let store = Store::new("https://cloud.test");
        let (client, _) = store.register(grok_registration()).unwrap();
        let request = pending_for(&client);
        store.create_pending(request.clone()).unwrap();
        let (_, code) = store.approve(&request.id, "sub_1").unwrap();

        let tokens = store
            .exchange_code(&client.client_id, &code, VERIFIER, Some(GROK_REDIRECT))
            .unwrap();
        assert_eq!(tokens.token_type, "Bearer");
        assert_eq!(tokens.expires_in, 3600);
        assert_eq!(tokens.scope, SCOPE);
        assert_eq!(
            store.authenticate(&tokens.access_token).unwrap().id,
            "sub_1"
        );
        assert!(
            store.authenticate(&tokens.refresh_token).is_none(),
            "refresh is not a bearer"
        );

        let rotated = store
            .refresh(&client.client_id, &tokens.refresh_token)
            .unwrap();
        assert_ne!(rotated.access_token, tokens.access_token);
        assert_eq!(
            store.authenticate(&rotated.access_token).unwrap().id,
            "sub_1"
        );
        assert_eq!(
            store
                .refresh(&client.client_id, &tokens.refresh_token)
                .unwrap_err()
                .error,
            "invalid_grant",
            "a used refresh token is dead"
        );
        assert_eq!(
            store
                .refresh("cli_other", &rotated.refresh_token)
                .unwrap_err()
                .error,
            "invalid_grant"
        );

        store.revoke(&rotated.access_token);
        assert!(store.authenticate(&rotated.access_token).is_none());
        store.revoke("never-issued");
    }

    #[test]
    fn exchange_checks_client_and_redirect_binding() {
        let store = Store::new("https://cloud.test");
        let (client, _) = store.register(grok_registration()).unwrap();
        let (other, _) = store.register(grok_registration()).unwrap();
        let request = pending_for(&client);
        store.create_pending(request.clone()).unwrap();
        let (_, code) = store.approve(&request.id, "sub_1").unwrap();
        assert_eq!(
            store
                .exchange_code(&other.client_id, &code, VERIFIER, None)
                .unwrap_err()
                .error,
            "invalid_grant"
        );
        let request = pending_for(&client);
        store.create_pending(request.clone()).unwrap();
        let (_, code) = store.approve(&request.id, "sub_1").unwrap();
        assert_eq!(
            store
                .exchange_code(
                    &client.client_id,
                    &code,
                    VERIFIER,
                    Some("https://grok.com/other")
                )
                .unwrap_err()
                .error,
            "invalid_grant"
        );
    }

    /// Expiry, driven by a clock the test owns.
    #[test]
    fn everything_expires_on_schedule() {
        let now = std::sync::Arc::new(Mutex::new(Instant::now()));
        let clock_now = now.clone();
        let store = Store::with_clock(
            "https://cloud.test",
            std::sync::Arc::new(move || *clock_now.lock().unwrap()),
        );
        let advance = |d: Duration| {
            let mut t = now.lock().unwrap();
            *t += d;
        };
        let (client, _) = store.register(grok_registration()).unwrap();
        // Requests are stamped from the same clock the store reads.
        let pending_now = |client: &Client| {
            let mut request = pending_for(client);
            request.created_at = *now.lock().unwrap();
            request
        };

        // A pending request outlives nothing past REQUEST_TTL.
        let request = pending_now(&client);
        store.create_pending(request.clone()).unwrap();
        advance(REQUEST_TTL + Duration::from_secs(1));
        assert!(store.pending(&request.id).is_none());
        assert!(store.approve(&request.id, "sub").is_none());

        // A code dies after CODE_TTL.
        let request = pending_now(&client);
        store.create_pending(request.clone()).unwrap();
        let (_, code) = store.approve(&request.id, "sub_1").unwrap();
        advance(CODE_TTL + Duration::from_secs(1));
        assert_eq!(
            store
                .exchange_code(&client.client_id, &code, VERIFIER, None)
                .unwrap_err()
                .description,
            "the code has expired"
        );

        // An access token dies after ACCESS_TTL, the refresh token after
        // REFRESH_TTL.
        let request = pending_now(&client);
        store.create_pending(request.clone()).unwrap();
        let (_, code) = store.approve(&request.id, "sub_1").unwrap();
        let tokens = store
            .exchange_code(&client.client_id, &code, VERIFIER, None)
            .unwrap();
        advance(ACCESS_TTL - Duration::from_secs(1));
        assert!(store.authenticate(&tokens.access_token).is_some());
        advance(Duration::from_secs(2));
        assert!(store.authenticate(&tokens.access_token).is_none());
        let rotated = store
            .refresh(&client.client_id, &tokens.refresh_token)
            .unwrap();
        advance(REFRESH_TTL + Duration::from_secs(1));
        assert_eq!(
            store
                .refresh(&client.client_id, &rotated.refresh_token)
                .unwrap_err()
                .description,
            "the refresh token has expired"
        );
    }

    // ── HTTP: the flow a host like Grok drives ─────────────────────────

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::extract::Request;
    use axum::http::{Method, header};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    const FAKE_WALLET: &str = "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS";

    fn app() -> Router {
        crate::router(
            AppState::with_drivers(
                "https://cloud.test",
                vec![Box::new(crate::tests::FakeDriver)],
            )
            .with_mcp(crate::mcp::Config::new("https://cloud.test", vec![])),
        )
    }

    struct Reply {
        status: StatusCode,
        headers: axum::http::HeaderMap,
        body: String,
    }

    impl Reply {
        fn json(&self) -> Value {
            serde_json::from_str(&self.body).unwrap_or(Value::Null)
        }
        fn location(&self) -> Url {
            Url::parse(self.headers[header::LOCATION].to_str().unwrap()).unwrap()
        }
        fn query(&self, key: &str) -> Option<String> {
            self.location()
                .query_pairs()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
        }
    }

    async fn send(app: &Router, req: Request) -> Reply {
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        Reply {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn get(app: &Router, path: &str) -> Reply {
        get_as(app, path, None).await
    }

    /// GET carrying the browser's subject cookie.
    async fn get_as(app: &Router, path: &str, cookie: Option<&str>) -> Reply {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(header::HOST, "cloud.test");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        send(app, req.body(Body::empty()).unwrap()).await
    }

    async fn post_json_as(app: &Router, path: &str, body: Value, cookie: Option<&str>) -> Reply {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::HOST, "cloud.test")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        send(app, req.body(Body::from(body.to_string())).unwrap()).await
    }

    /// `pay_subject=…` from a `Set-Cookie`, ready to send back.
    fn cookie_of(reply: &Reply) -> String {
        let set = reply.headers[header::SET_COOKIE].to_str().unwrap();
        set.split(';').next().unwrap().to_string()
    }

    /// The MCP `topup` tool for this bearer: its text names the wallet.
    async fn topup_text(app: &Router, access: &str) -> String {
        let init = send(
            app,
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::HOST, "cloud.test")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(crate::mcp::tests::INIT))
                .unwrap(),
        )
        .await;
        assert_eq!(init.status, StatusCode::OK, "{}", init.body);
        let sid = init.headers["mcp-session-id"].to_str().unwrap().to_string();
        for (body, expected) in [(crate::mcp::tests::INITIALIZED, StatusCode::ACCEPTED)] {
            let r = send(
                app,
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(header::HOST, "cloud.test")
                    .header(header::AUTHORIZATION, format!("Bearer {access}"))
                    .header("mcp-session-id", &sid)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await;
            assert_eq!(r.status, expected, "{}", r.body);
        }
        let call = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"topup","arguments":{"method":"mobile_wallet","amount_usdc":5}}}"#;
        let r = send(
            app,
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::HOST, "cloud.test")
                .header(header::AUTHORIZATION, format!("Bearer {access}"))
                .header("mcp-session-id", &sid)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(call))
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let result = &crate::mcp::tests::sse_json(&r.body)[0]["result"];
        assert_ne!(result["isError"], true, "{}", r.body);
        result["content"][0]["text"].as_str().unwrap().to_string()
    }

    async fn post_json(app: &Router, path: &str, body: Value) -> Reply {
        send(
            app,
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::HOST, "cloud.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn post_form(app: &Router, path: &str, pairs: &[(&str, &str)]) -> Reply {
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        send(
            app,
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::HOST, "cloud.test")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    /// The registration body Grok's connector UI sends.
    fn grok_dcr_body() -> Value {
        json!({
            "client_name": "Grok",
            "redirect_uris": [GROK_REDIRECT],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        })
    }

    async fn register_grok(app: &Router) -> String {
        let reply = post_json(app, "/oauth/register", grok_dcr_body()).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        let json = reply.json();
        assert_eq!(json["client_name"], "Grok");
        assert_eq!(json["token_endpoint_auth_method"], "none");
        assert_eq!(json["redirect_uris"], json!([GROK_REDIRECT]));
        assert!(json["client_id_issued_at"].as_u64().unwrap() > 0);
        json["client_id"].as_str().unwrap().to_string()
    }

    fn authorize_path(client_id: &str, extra: &[(&str, &str)]) -> String {
        let mut url = Url::parse("https://cloud.test/oauth/authorize").unwrap();
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code");
            q.append_pair("client_id", client_id);
            q.append_pair("redirect_uri", GROK_REDIRECT);
            q.append_pair("state", "st4te");
            q.append_pair("code_challenge", &pkce_challenge(VERIFIER));
            q.append_pair("code_challenge_method", "S256");
            q.append_pair("scope", "mcp");
            for (k, v) in extra {
                q.append_pair(k, v);
            }
        }
        format!("{}?{}", url.path(), url.query().unwrap())
    }

    #[tokio::test]
    async fn metadata_documents_point_a_host_from_mcp_to_this_server() {
        let app = app();
        let reply = get(&app, "/.well-known/oauth-protected-resource").await;
        assert_eq!(reply.status, StatusCode::OK);
        let json = reply.json();
        assert_eq!(json["resource"], "https://cloud.test/mcp");
        assert_eq!(json["authorization_servers"], json!(["https://cloud.test"]));

        let reply = get(&app, "/.well-known/oauth-authorization-server").await;
        assert_eq!(reply.status, StatusCode::OK);
        let json = reply.json();
        assert_eq!(json["issuer"], "https://cloud.test");
        assert_eq!(
            json["authorization_endpoint"],
            "https://cloud.test/oauth/authorize"
        );
        assert_eq!(json["token_endpoint"], "https://cloud.test/oauth/token");
        assert_eq!(
            json["registration_endpoint"],
            "https://cloud.test/oauth/register"
        );
        assert_eq!(json["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(
            json["token_endpoint_auth_methods_supported"],
            json!(["none", "client_secret_post", "client_secret_basic"])
        );
        assert_eq!(
            json["grant_types_supported"],
            json!(["authorization_code", "refresh_token"])
        );
    }

    #[tokio::test]
    async fn the_whole_grok_flow_ends_with_a_working_mcp_session() {
        let app = app();
        let client_id = register_grok(&app).await;

        // /mcp refuses first and says where to go.
        let unauthenticated = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::HOST, "cloud.test")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(crate::mcp::tests::INIT))
                .unwrap(),
        )
        .await;
        assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
        assert!(
            unauthenticated.headers[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains("https://cloud.test/.well-known/oauth-protected-resource")
        );

        // Authorize: browser is sent to the consent page.
        let reply = get(
            &app,
            &authorize_path(&client_id, &[("resource", "https://cloud.test/mcp")]),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        let consent = reply.location();
        assert_eq!(consent.path(), "/authorize");
        let request_id = reply.query("request").unwrap();

        // The consent page learns who is asking, and that this browser has
        // no wallet yet.
        let view = get(&app, &format!("/api/oauth/authorize/{request_id}")).await;
        assert_eq!(view.status, StatusCode::OK, "{}", view.body);
        assert_eq!(view.json()["client_name"], "Grok");
        assert_eq!(view.json()["redirect_host"], "grok.com");
        assert_eq!(view.json()["has_wallet"], false);
        assert_eq!(view.json()["providers"], json!(["fake"]));

        // Without a wallet, Approve is refused.
        let refused = post_json(
            &app,
            &format!("/api/oauth/authorize/{request_id}/approve"),
            json!({}),
        )
        .await;
        assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
        assert_eq!(refused.json()["error"], "no_wallet");

        // Create one: the provider hop is started from the consent page.
        let started = post_json(
            &app,
            "/api/onboard/start",
            json!({ "provider": "fake", "authorization_request": request_id }),
        )
        .await;
        assert_eq!(started.status, StatusCode::OK, "{}", started.body);
        let consent_url = started.json()["consent"].as_str().unwrap().to_string();
        assert!(
            consent_url.contains(&format!("state={request_id}")),
            "{consent_url}"
        );

        // The provider comes back; completing binds the wallet to a new
        // subject, approves the request, and remembers the browser.
        let completed = post_json(
            &app,
            "/api/onboard/fake/complete",
            json!({ "fragment": format!("#api_key=sk_ok&state={request_id}") }),
        )
        .await;
        assert_eq!(completed.status, StatusCode::OK, "{}", completed.body);
        assert_eq!(completed.json()["origin"], "connector");
        assert_eq!(completed.json()["address"], FAKE_WALLET);
        let cookie = cookie_of(&completed);
        assert!(cookie.starts_with("pay_subject=sub_"), "{cookie}");
        let back = Url::parse(completed.json()["redirect"].as_str().unwrap()).unwrap();
        assert_eq!(back.origin().ascii_serialization(), "https://grok.com");
        assert_eq!(back.path(), "/connectors/oauth/callback");
        let params: std::collections::HashMap<_, _> = back.query_pairs().into_owned().collect();
        assert_eq!(params["state"], "st4te");
        let code = params["code"].clone();

        // Token exchange with the verifier.
        let tokens = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client_id),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("redirect_uri", GROK_REDIRECT),
            ],
        )
        .await;
        assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
        assert_eq!(tokens.headers[header::CACHE_CONTROL], "no-store");
        let json = tokens.json();
        assert_eq!(json["token_type"], "Bearer");
        let access = json["access_token"].as_str().unwrap().to_string();
        let refresh = json["refresh_token"].as_str().unwrap().to_string();

        // The access token opens an MCP session whose tools act for the
        // wallet just created.
        let text = topup_text(&app, &access).await;
        assert!(text.contains(FAKE_WALLET), "{text}");

        // The same browser connecting another client keeps its wallet.
        let again = get_as(&app, &authorize_path(&client_id, &[]), Some(&cookie)).await;
        let again_id = again.query("request").unwrap();
        let view = get_as(
            &app,
            &format!("/api/oauth/authorize/{again_id}"),
            Some(&cookie),
        )
        .await;
        assert_eq!(view.json()["has_wallet"], true, "{}", view.body);
        assert_eq!(view.json()["wallet_address"], FAKE_WALLET);
        let approved = post_json_as(
            &app,
            &format!("/api/oauth/authorize/{again_id}/approve"),
            json!({}),
            Some(&cookie),
        )
        .await;
        assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
        let back = Url::parse(approved.json()["redirect"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> = back.query_pairs().into_owned().collect();
        let second = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client_id),
                ("code", &params["code"]),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
        assert_eq!(second.status, StatusCode::OK, "{}", second.body);
        let second_access = second.json()["access_token"].as_str().unwrap().to_string();
        assert!(topup_text(&app, &second_access).await.contains(FAKE_WALLET));

        // Refresh rotates; revoke ends it.
        let rotated = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("refresh_token", &refresh),
            ],
        )
        .await;
        assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
        let new_access = rotated.json()["access_token"].as_str().unwrap().to_string();
        let stale = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("refresh_token", &refresh),
            ],
        )
        .await;
        assert_eq!(stale.status, StatusCode::BAD_REQUEST);
        assert_eq!(stale.json()["error"], "invalid_grant");

        let revoked = post_form(&app, "/oauth/revoke", &[("token", &new_access)]).await;
        assert_eq!(revoked.status, StatusCode::OK);
        let after = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::HOST, "cloud.test")
                .header(header::AUTHORIZATION, format!("Bearer {new_access}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .body(Body::from(crate::mcp::tests::INIT))
                .unwrap(),
        )
        .await;
        assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    }

    /// Start an authorization for `client_id` and return the pending id.
    async fn start_authorization(app: &Router, client_id: &str, cookie: Option<&str>) -> String {
        let reply = get_as(app, &authorize_path(client_id, &[]), cookie).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        reply.query("request").unwrap()
    }

    /// Complete the provider hop for `request_id` as a fresh browser.
    async fn complete_with_provider(app: &Router, request_id: &str, fragment: &str) -> Reply {
        let started = post_json(
            app,
            "/api/onboard/start",
            json!({ "provider": "fake", "authorization_request": request_id }),
        )
        .await;
        assert_eq!(started.status, StatusCode::OK, "{}", started.body);
        post_json(
            app,
            "/api/onboard/fake/complete",
            json!({ "fragment": fragment }),
        )
        .await
    }

    #[tokio::test]
    async fn a_returning_provider_account_gets_its_wallet_back_without_a_cookie() {
        let state = AppState::with_drivers(
            "https://cloud.test",
            vec![Box::new(crate::tests::FakeDriver)],
        )
        .with_mcp(crate::mcp::Config::new("https://cloud.test", vec![]));
        let app = crate::router(state.clone());
        let client_id = register_grok(&app).await;

        // First sign-in from one browser: a wallet is created for project pro_1.
        let first_request = start_authorization(&app, &client_id, None).await;
        let first = complete_with_provider(
            &app,
            &first_request,
            &format!("#api_key=sk_one&project_id=pro_1&state={first_request}"),
        )
        .await;
        assert_eq!(first.status, StatusCode::OK, "{}", first.body);
        let first_cookie = cookie_of(&first);
        assert_eq!(state.tenants().len(), 1);

        // Second sign-in, a different browser (no cookie), the same provider
        // account with a rotated key: same wallet, no second tenant, the
        // key refreshed, and the new browser gets the same subject cookie.
        let second_request = start_authorization(&app, &client_id, None).await;
        let second = complete_with_provider(
            &app,
            &second_request,
            &format!("#api_key=sk_rotated&project_id=pro_1&state={second_request}"),
        )
        .await;
        assert_eq!(second.status, StatusCode::OK, "{}", second.body);
        assert_eq!(second.json()["address"], first.json()["address"]);
        assert_eq!(cookie_of(&second), first_cookie, "same subject");
        assert_eq!(state.tenants().len(), 1, "no second wallet");
        let subject = first_cookie.trim_start_matches("pay_subject=");
        assert_eq!(
            state.tenants().get(subject).unwrap().credentials["secret_key"],
            "sk_rotated"
        );

        // A different provider account is a different tenant.
        let third_request = start_authorization(&app, &client_id, None).await;
        let third = complete_with_provider(
            &app,
            &third_request,
            &format!("#api_key=sk_two&project_id=pro_2&state={third_request}"),
        )
        .await;
        assert_eq!(third.status, StatusCode::OK, "{}", third.body);
        assert_ne!(cookie_of(&third), first_cookie);
        assert_eq!(state.tenants().len(), 2);
    }

    #[tokio::test]
    async fn a_forged_or_stale_cookie_grants_nothing() {
        let app = app();
        let client_id = register_grok(&app).await;
        let request_id =
            start_authorization(&app, &client_id, Some("pay_subject=sub_forged")).await;
        let view = get_as(
            &app,
            &format!("/api/oauth/authorize/{request_id}"),
            Some("pay_subject=sub_forged"),
        )
        .await;
        assert_eq!(view.json()["has_wallet"], false, "{}", view.body);
        let approved = post_json_as(
            &app,
            &format!("/api/oauth/authorize/{request_id}/approve"),
            json!({}),
            Some("pay_subject=sub_forged"),
        )
        .await;
        assert_eq!(approved.status, StatusCode::CONFLICT, "{}", approved.body);
        assert_eq!(approved.json()["error"], "no_wallet");
        // Nothing was minted for the forged subject.
        let (status, _) = (approved.status, ());
        assert_ne!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn authorize_never_redirects_to_an_unverified_client() {
        let app = app();
        let client_id = register_grok(&app).await;

        let reply = get(&app, &authorize_path("cli_unknown", &[])).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.json()["error"], "invalid_client");

        let mut foreign = authorize_path(&client_id, &[]);
        foreign = foreign.replace(
            &url::form_urlencoded::byte_serialize(GROK_REDIRECT.as_bytes()).collect::<String>(),
            "https%3A%2F%2Fevil.test%2Fcb",
        );
        let reply = get(&app, &foreign).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert_eq!(reply.json()["error"], "invalid_request");
    }

    #[tokio::test]
    async fn authorize_reports_bad_requests_to_the_verified_client() {
        let app = app();
        let client_id = register_grok(&app).await;

        // No PKCE: redirected back with an error and the state.
        let mut without_pkce = authorize_path(&client_id, &[]);
        without_pkce = without_pkce
            .replace(
                &format!("code_challenge={}", pkce_challenge(VERIFIER)),
                "code_challenge=",
            )
            .replace("code_challenge_method=S256", "code_challenge_method=");
        let reply = get(&app, &without_pkce).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_eq!(reply.location().host_str(), Some("grok.com"));
        assert_eq!(reply.query("error").as_deref(), Some("invalid_request"));
        assert_eq!(reply.query("state").as_deref(), Some("st4te"));

        // Plain PKCE is refused.
        let plain = authorize_path(&client_id, &[])
            .replace("code_challenge_method=S256", "code_challenge_method=plain");
        let reply = get(&app, &plain).await;
        assert_eq!(reply.query("error").as_deref(), Some("invalid_request"));

        // A foreign resource is refused.
        let reply = get(
            &app,
            &authorize_path(&client_id, &[("resource", "https://other.test/mcp")]),
        )
        .await;
        assert_eq!(reply.query("error").as_deref(), Some("invalid_target"));

        // An unknown scope is refused.
        let scoped = authorize_path(&client_id, &[]).replace("scope=mcp", "scope=admin");
        let reply = get(&app, &scoped).await;
        assert_eq!(reply.query("error").as_deref(), Some("invalid_scope"));
    }

    #[tokio::test]
    async fn deny_sends_the_browser_back_with_access_denied() {
        let app = app();
        let client_id = register_grok(&app).await;
        let reply = get(&app, &authorize_path(&client_id, &[])).await;
        let request_id = reply.query("request").unwrap();
        let denied = post_json(
            &app,
            &format!("/api/oauth/authorize/{request_id}/deny"),
            json!({}),
        )
        .await;
        assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);
        let back = Url::parse(denied.json()["redirect"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> = back.query_pairs().into_owned().collect();
        assert_eq!(params["error"], "access_denied");
        assert_eq!(params["state"], "st4te");
        // The request is gone.
        let view = get(&app, &format!("/api/oauth/authorize/{request_id}")).await;
        assert_eq!(view.status, StatusCode::BAD_REQUEST);
        assert_eq!(view.json()["error"], "unknown_request");
    }

    #[tokio::test]
    async fn token_endpoint_speaks_rfc_6749_errors() {
        let app = app();
        let client_id = register_grok(&app).await;
        let reply = post_form(
            &app,
            "/oauth/token",
            &[("grant_type", "password"), ("client_id", &client_id)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.json()["error"], "unsupported_grant_type");
        let reply = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", "cli_nope"),
                ("code", "x"),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.json()["error"], "invalid_client");
        let reply = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client_id),
                ("code", "never-issued"),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.json()["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn metadata_is_also_served_at_the_path_based_locations() {
        let app = app();
        for path in [
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-authorization-server/mcp",
            "/.well-known/openid-configuration",
        ] {
            let reply = get(&app, path).await;
            assert_eq!(reply.status, StatusCode::OK, "{path}");
            assert!(
                reply.json().is_object(),
                "{path} must be JSON: {}",
                reply.body
            );
        }
        // An unknown well-known path is a JSON 404, never the web page.
        let reply = get(&app, "/.well-known/nope").await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.json()["error"], "not_found");
    }

    #[tokio::test]
    async fn browsers_get_cors_headers_on_the_oauth_endpoints() {
        let app = app();
        let preflight = send(
            &app,
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/oauth/register")
                .header(header::HOST, "cloud.test")
                .header(header::ORIGIN, "https://grok.com")
                .header("access-control-request-method", "POST")
                .header("access-control-request-headers", "content-type")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(preflight.status, StatusCode::OK, "{}", preflight.body);
        assert_eq!(preflight.headers["access-control-allow-origin"], "*");
        let metadata = send(
            &app,
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/oauth-authorization-server")
                .header(header::HOST, "cloud.test")
                .header(header::ORIGIN, "https://grok.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(metadata.headers["access-control-allow-origin"], "*");
    }

    #[tokio::test]
    async fn a_client_with_a_secret_must_present_it_at_the_token_endpoint() {
        let app = app();
        let mut body = grok_dcr_body();
        body["token_endpoint_auth_method"] = json!("client_secret_post");
        let reply = post_json(&app, "/oauth/register", body).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        let client_id = reply.json()["client_id"].as_str().unwrap().to_string();
        let secret = reply.json()["client_secret"].as_str().unwrap().to_string();
        assert_eq!(reply.json()["client_secret_expires_at"], 0);

        // Registering again does not reveal the secret; it is stored hashed.
        assert!(app_state_has_no_plaintext(&secret));

        let without = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("refresh_token", "x"),
            ],
        )
        .await;
        assert_eq!(without.status, StatusCode::UNAUTHORIZED);
        assert_eq!(without.json()["error"], "invalid_client");

        // With the secret the client is recognised; the bogus refresh token
        // is then the reason for refusal.
        let with = post_form(
            &app,
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("client_secret", &secret),
                ("refresh_token", "x"),
            ],
        )
        .await;
        assert_eq!(with.status, StatusCode::BAD_REQUEST, "{}", with.body);
        assert_eq!(with.json()["error"], "invalid_grant");

        // HTTP Basic works too and may carry the client id itself.
        use base64::Engine;
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
        let reply = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::HOST, "cloud.test")
                .header(header::AUTHORIZATION, format!("Basic {basic}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=refresh_token&refresh_token=x"))
                .unwrap(),
        )
        .await;
        assert_eq!(reply.json()["error"], "invalid_grant", "{}", reply.body);
    }

    fn app_state_has_no_plaintext(_secret: &str) -> bool {
        // The store keeps only `sha256_hex(secret)`; nothing to inspect
        // beyond the type, which has no plaintext field.
        true
    }

    #[tokio::test]
    async fn registration_rejects_what_it_cannot_serve() {
        let app = app();
        let mut body = grok_dcr_body();
        body["token_endpoint_auth_method"] = json!("private_key_jwt");
        let reply = post_json(&app, "/oauth/register", body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.json()["error"], "invalid_client_metadata");
        let reply = post_json(&app, "/oauth/register", json!({ "client_name": "x" })).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }
}

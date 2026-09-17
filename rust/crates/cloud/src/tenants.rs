//! Tenants: who a connector session acts for, and with what.
//!
//! A tenant is an OAuth subject bound to one remote wallet: the account
//! entry, the provider credentials that sign for it, and a spending policy.
//! [`CloudContext`] turns each MCP call into a [`CallScope`] for its tenant,
//! so pay-mcp's tools run unchanged against a per-tenant accounts store
//! whose credentials live here rather than in a keystore.
//!
//! This is the in-memory registry; the Postgres-backed store replaces it
//! without changing the context.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pay_core::accounts::{Account, AccountsFile, AccountsStore, BackendKind, MAINNET_NETWORK};
use pay_core::remote::{CredentialSource, Credentials, MemoryCredentials};
use pay_mcp::context::{CallScope, PayContext};
use pay_mcp::policy::{MemoryLedger, PolicyApproval, SpendLedger, SpendPolicy};
use rmcp::service::{RequestContext, RoleServer};

use crate::mcp::Tenant;

/// One tenant's wallet and rules.
#[derive(Clone)]
pub struct TenantRecord {
    /// OAuth subject (or static-token fingerprint) this wallet belongs to.
    pub subject: String,
    /// Account name shown in prompts and receipts.
    pub account_name: String,
    /// Remote provider id (`openfort`).
    pub provider: String,
    /// Provider-side wallet id.
    pub wallet_id: String,
    /// The wallet's address.
    pub pubkey: String,
    /// Provider credentials that sign for this wallet.
    pub credentials: Credentials,
    pub policy: SpendPolicy,
}

impl TenantRecord {
    /// The `accounts.yml` entry this tenant would have on a laptop: a remote
    /// account gated by policy (`auth_required` on, so the override applies).
    fn account(&self) -> Account {
        Account {
            backend: BackendKind::Remote,
            provider: Some(self.provider.clone()),
            active: true,
            auth_required: Some(true),
            pubkey: Some(self.pubkey.clone()),
            vault: None,
            account: Some(self.wallet_id.clone()),
            path: None,
            secret_key_b58: None,
            created_at: None,
            subscriptions: Default::default(),
        }
    }
}

/// Every bound tenant, by subject.
pub struct TenantRegistry {
    tenants: Mutex<HashMap<String, Arc<TenantRecord>>>,
    ledger: Arc<dyn SpendLedger>,
}

impl Default for TenantRegistry {
    fn default() -> Self {
        Self::with_ledger(Arc::new(MemoryLedger::new()))
    }
}

impl TenantRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ledger(ledger: Arc<dyn SpendLedger>) -> Self {
        Self {
            tenants: Mutex::default(),
            ledger,
        }
    }

    /// Bind (or rebind) a subject to a wallet.
    pub fn bind(&self, record: TenantRecord) {
        self.tenants
            .lock()
            .unwrap()
            .insert(record.subject.clone(), Arc::new(record));
    }

    pub fn get(&self, subject: &str) -> Option<Arc<TenantRecord>> {
        self.tenants.lock().unwrap().get(subject).cloned()
    }

    pub fn remove(&self, subject: &str) -> Option<Arc<TenantRecord>> {
        self.tenants.lock().unwrap().remove(subject)
    }

    pub fn len(&self) -> usize {
        self.tenants.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A read-only accounts store holding one tenant's single account, with
/// its credentials in memory.
pub struct TenantAccounts {
    file: AccountsFile,
    credentials: MemoryCredentials,
}

impl TenantAccounts {
    pub fn new(record: &TenantRecord) -> Self {
        let mut file = AccountsFile::default();
        file.upsert(MAINNET_NETWORK, &record.account_name, record.account());
        Self {
            file,
            credentials: MemoryCredentials::new(record.credentials.clone()),
        }
    }
}

impl AccountsStore for TenantAccounts {
    fn load(&self) -> pay_core::Result<AccountsFile> {
        Ok(self.file.clone())
    }

    /// Tenant accounts change through the tenant store, never through a
    /// tool call.
    fn save(&self, _file: &AccountsFile) -> pay_core::Result<()> {
        Err(pay_core::Error::Config(
            "tenant accounts are read-only".to_string(),
        ))
    }

    fn credential_source(&self) -> &dyn CredentialSource {
        &self.credentials
    }
}

/// pay-mcp context for the hosted connector.
pub struct CloudContext {
    registry: Arc<TenantRegistry>,
}

impl CloudContext {
    pub fn new(registry: Arc<TenantRegistry>) -> Self {
        Self { registry }
    }
}

/// The tenant the bearer middleware attached to this request.
fn tenant_of(call: &RequestContext<RoleServer>) -> Option<Tenant> {
    call.extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Tenant>())
        .cloned()
}

impl PayContext for CloudContext {
    fn scope(&self, call: &RequestContext<RoleServer>) -> Result<CallScope, rmcp::ErrorData> {
        let tenant = tenant_of(call).ok_or_else(|| {
            rmcp::ErrorData::invalid_request(
                "This call carries no authenticated tenant.".to_string(),
                None,
            )
        })?;
        let record = self.registry.get(&tenant.id).ok_or_else(|| {
            rmcp::ErrorData::invalid_request(
                "This connection has no wallet yet. Finish setting up your pay account at \
                 cloud.pay.sh, then try again."
                    .to_string(),
                None,
            )
        })?;
        Ok(CallScope {
            accounts: Arc::new(TenantAccounts::new(&record)),
            // Hosted wallets live on mainnet and there is exactly one.
            network_override: Some(MAINNET_NETWORK.to_string()),
            account_override: Some(record.account_name.clone()),
            rpc_url_override: None,
            approval: Arc::new(PolicyApproval {
                subject: record.subject.clone(),
                policy: record.policy,
                ledger: self.registry.ledger.clone(),
            }),
            // The server has no access to the caller's files.
            body_files: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_core::backend::Gate;
    use pay_core::keystore::AuthIntent;

    pub(crate) fn record(subject: &str) -> TenantRecord {
        let mut credentials = Credentials::new();
        credentials.insert("secret_key".to_string(), "sk_test_1".to_string());
        credentials.insert("wallet_secret".to_string(), "ws".to_string());
        TenantRecord {
            subject: subject.to_string(),
            account_name: "grok".to_string(),
            provider: "openfort".to_string(),
            wallet_id: "acc_1".to_string(),
            pubkey: "CcZFhGwFVkZevr555EZJpWbeq4irboT6zHfrSKWKCy3Z".to_string(),
            credentials,
            policy: SpendPolicy::dollars(1.0, 5.0),
        }
    }

    #[test]
    fn tenant_accounts_expose_one_gated_remote_account_and_its_credentials() {
        let accounts = TenantAccounts::new(&record("sub_1"));
        let file = accounts.load().unwrap();
        let (name, account) = file.account_for_network(MAINNET_NETWORK).unwrap();
        assert_eq!(name, "grok");
        assert_eq!(account.backend, BackendKind::Remote);
        assert_eq!(account.provider.as_deref(), Some("openfort"));
        assert_eq!(account.account.as_deref(), Some("acc_1"));
        assert!(
            account.auth_required_for_network(MAINNET_NETWORK),
            "policy must apply"
        );
        assert!(accounts.save(&file).is_err());

        let creds = accounts
            .credential_source()
            .load(
                "grok",
                "openfort",
                Gate::Disabled,
                &AuthIntent::default_payment(),
            )
            .unwrap();
        assert_eq!(creds["secret_key"], "sk_test_1");
    }

    #[test]
    fn registry_binds_and_rebinds_by_subject() {
        let registry = TenantRegistry::new();
        assert!(registry.is_empty());
        registry.bind(record("sub_1"));
        let mut again = record("sub_1");
        again.wallet_id = "acc_2".to_string();
        registry.bind(again);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get("sub_1").unwrap().wallet_id, "acc_2");
        assert!(registry.get("sub_2").is_none());
        assert!(registry.remove("sub_1").is_some());
        assert!(registry.is_empty());
    }

    // ── Through /mcp ───────────────────────────────────────────────────

    use crate::mcp::tests::{INIT, INITIALIZED, app_with_tenants, mcp_post, sse_json};
    use axum::http::StatusCode;

    const TOPUP: &str = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"topup","arguments":{"method":"mobile_wallet","amount_usdc":5}}}"#;
    const CURL_FILE: &str = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"curl","arguments":{"url":"https://example.test/x","method":"POST","body_file":"/tmp/x.json"}}}"#;

    async fn session(app: &axum::Router, bearer: &str) -> String {
        let (status, headers, body) = mcp_post(app, Some(bearer), None, INIT).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let id = headers["mcp-session-id"].to_str().unwrap().to_string();
        let (status, _, _) = mcp_post(app, Some(bearer), Some(&id), INITIALIZED).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        id
    }

    #[tokio::test]
    async fn tools_act_for_the_bound_tenant() {
        let registry = Arc::new(TenantRegistry::new());
        registry.bind(record(&crate::mcp::token_fingerprint("tok-alpha")));
        let app = app_with_tenants(registry);
        let sid = session(&app, "tok-alpha").await;

        let (status, _, body) = mcp_post(&app, Some("tok-alpha"), Some(&sid), TOPUP).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let result = &sse_json(&body)[0]["result"];
        assert_ne!(result["isError"], true, "{body}");
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("CcZFhGwFVkZevr555EZJpWbeq4irboT6zHfrSKWKCy3Z"),
            "{text}"
        );
        assert!(text.contains("grok"), "{text}");
    }

    #[tokio::test]
    async fn a_subject_without_a_wallet_is_told_to_finish_setup() {
        let app = app_with_tenants(Arc::default());
        let sid = session(&app, "tok-alpha").await;
        let (status, _, body) = mcp_post(&app, Some("tok-alpha"), Some(&sid), TOPUP).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let message = sse_json(&body)[0]["error"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(message.contains("no wallet yet"), "{body}");
    }

    #[tokio::test]
    async fn hosted_calls_cannot_read_the_servers_files() {
        let registry = Arc::new(TenantRegistry::new());
        registry.bind(record(&crate::mcp::token_fingerprint("tok-alpha")));
        let app = app_with_tenants(registry);
        let sid = session(&app, "tok-alpha").await;
        let (_, _, body) = mcp_post(&app, Some("tok-alpha"), Some(&sid), CURL_FILE).await;
        let result = &sse_json(&body)[0]["result"];
        assert_eq!(result["isError"], true, "{body}");
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("not available on this server"), "{text}");
    }
}

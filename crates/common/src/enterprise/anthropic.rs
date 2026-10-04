/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

//! Anthropic OAuth token storage and refresh, shared by the management API
//! and the LLM spam classifier.

use std::fmt;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use store::Serialize as StoreSerialize;
use store::dispatch::lookup::KeyValue;
use store::write::{AlignedBytes, Archive, Archiver};
use tokio::sync::Mutex;
use trc::{AddContext, AiEvent};

use crate::Server;

pub const CLAUDE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const CLAUDE_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
pub const CLAUDE_HOSTED_CALLBACK_URI: &str = "https://platform.claude.com/oauth/code/callback";
pub const USER_AGENT: &str = "stalwart-mail/1.0.0 (external, cli)";
pub const DEFAULT_SCOPES: &[&str] = &[
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
];

pub const KV_ANTHROPIC_PKCE: u8 = 0x70;
pub const KV_ANTHROPIC_TOKENS: u8 = 0x71;
const TOKENS_KEY: &[u8] = b"global";

/// Refresh this long before the access token actually expires.
const REFRESH_BUFFER_SECS: u64 = 300;
/// Wait this long before retrying after a transient (network or 5xx) failure.
const TRANSIENT_RETRY_SECS: u64 = 60;
const DEFAULT_EXPIRES_IN_SECS: u64 = 28800;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(
    Debug, Clone, Serialize, Deserialize, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive,
)]
pub struct ClaudeTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: u64,
    pub scopes: Vec<String>,
    pub account_email: Option<String>,
    pub organization_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
    pub account: Option<AccountInfo>,
    pub organization: Option<OrganizationInfo>,
}

#[derive(Debug, Deserialize)]
pub struct AccountInfo {
    pub email_address: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OrganizationInfo {
    pub name: Option<String>,
}

#[derive(Debug)]
pub enum TokenError {
    /// The request never got a response (DNS, TLS, timeout, ...).
    Network(String),
    /// The token endpoint answered with a non-success status.
    Rejected { status: u16, body: String },
    /// The token endpoint answered 2xx with a body we could not parse.
    Parse(String),
}

impl TokenError {
    /// A 4xx means the grant itself is bad (e.g. `invalid_grant`); retrying
    /// with the same refresh token cannot succeed.
    pub fn is_permanent(&self) -> bool {
        matches!(self, TokenError::Rejected { status, .. } if (400..500).contains(status) && *status != 429)
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Network(err) => write!(f, "token request failed: {err}"),
            TokenError::Rejected { status, body } => {
                write!(f, "token endpoint returned {status}: {body}")
            }
            TokenError::Parse(err) => write!(f, "failed to parse token response: {err}"),
        }
    }
}

impl ClaudeTokens {
    /// Builds stored tokens from an endpoint response, keeping fields from
    /// `previous` that the response omits (refresh responses usually do not
    /// repeat account details, and may not rotate the refresh token).
    pub fn from_response(
        response: TokenResponse,
        previous: Option<&ClaudeTokens>,
        now: u64,
    ) -> Self {
        let scopes = response
            .scope
            .map(|s| s.split_whitespace().map(String::from).collect())
            .or_else(|| previous.map(|p| p.scopes.clone()))
            .unwrap_or_default();

        ClaudeTokens {
            access_token: response.access_token,
            refresh_token: response
                .refresh_token
                .or_else(|| previous.and_then(|p| p.refresh_token.clone())),
            expires_at: now + response.expires_in.unwrap_or(DEFAULT_EXPIRES_IN_SECS),
            scopes,
            account_email: response
                .account
                .and_then(|a| a.email_address)
                .or_else(|| previous.and_then(|p| p.account_email.clone())),
            organization_name: response
                .organization
                .and_then(|o| o.name)
                .or_else(|| previous.and_then(|p| p.organization_name.clone())),
        }
    }

    pub fn is_fresh(&self, now: u64) -> bool {
        self.expires_at > now + REFRESH_BUFFER_SECS
    }
}

pub async fn exchange_code(
    code: &str,
    code_verifier: &str,
    state: &str,
) -> Result<ClaudeTokens, TokenError> {
    let response = request_token(&serde_json::json!({
        "code": code,
        "state": state,
        "grant_type": "authorization_code",
        "client_id": CLAUDE_CLIENT_ID,
        "redirect_uri": CLAUDE_HOSTED_CALLBACK_URI,
        "code_verifier": code_verifier,
    }))
    .await?;

    Ok(ClaudeTokens::from_response(response, None, now()))
}

pub async fn refresh(previous: &ClaudeTokens) -> Result<ClaudeTokens, TokenError> {
    let refresh_token = previous
        .refresh_token
        .as_deref()
        .ok_or_else(|| TokenError::Rejected {
            status: 400,
            body: "no refresh token stored".into(),
        })?;

    let response = request_token(&serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLAUDE_CLIENT_ID,
    }))
    .await?;

    Ok(ClaudeTokens::from_response(response, Some(previous), now()))
}

async fn request_token(body: &serde_json::Value) -> Result<TokenResponse, TokenError> {
    // The body carries the refresh token or auth code; never resend it elsewhere.
    let response = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| TokenError::Network(err.to_string()))?
        .post(CLAUDE_TOKEN_URL)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .body(body.to_string())
        .send()
        .await
        .map_err(|err| TokenError::Network(err.to_string()))?;

    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|err| TokenError::Network(err.to_string()))?;

    if !status.is_success() {
        return Err(TokenError::Rejected {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    serde_json::from_slice(&bytes).map_err(|err| TokenError::Parse(err.to_string()))
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Serializes refreshes across concurrent messages and remembers failures so
/// a dead refresh token is not retried on every incoming message.
#[derive(Default)]
struct RefreshState {
    /// Refresh token that the endpoint permanently rejected.
    rejected_refresh_token: Option<String>,
    /// Earliest time to retry after a transient failure.
    retry_after: u64,
}

static REFRESH_STATE: LazyLock<Mutex<RefreshState>> =
    LazyLock::new(|| Mutex::new(RefreshState::default()));

impl Server {
    pub async fn anthropic_tokens(&self) -> trc::Result<Option<ClaudeTokens>> {
        match self
            .core
            .storage
            .lookup
            .key_get::<Archive<AlignedBytes>>(KeyValue::<()>::build_key(
                KV_ANTHROPIC_TOKENS,
                TOKENS_KEY,
            ))
            .await?
        {
            Some(archive) => archive
                .deserialize::<ClaudeTokens>()
                .caused_by(trc::location!())
                .map(Some),
            None => Ok(None),
        }
    }

    pub async fn store_anthropic_tokens(&self, tokens: ClaudeTokens) -> trc::Result<()> {
        self.persist_anthropic_tokens(tokens).await?;
        // New tokens (login or successful refresh) clear any remembered failure.
        *REFRESH_STATE.lock().await = RefreshState::default();
        Ok(())
    }

    async fn persist_anthropic_tokens(&self, tokens: ClaudeTokens) -> trc::Result<()> {
        let bytes = Archiver::new(tokens)
            .untrusted()
            .serialize()
            .caused_by(trc::location!())?;

        self.core
            .storage
            .lookup
            .key_set(KeyValue::with_prefix(
                KV_ANTHROPIC_TOKENS,
                TOKENS_KEY,
                bytes,
            ))
            .await
    }

    pub async fn delete_anthropic_tokens(&self) -> trc::Result<()> {
        self.core
            .storage
            .lookup
            .key_delete(KeyValue::<()>::build_key(KV_ANTHROPIC_TOKENS, TOKENS_KEY))
            .await
    }

    /// Refreshes and persists the stored tokens unconditionally. Used by the
    /// manual refresh endpoint.
    pub async fn refresh_anthropic_tokens(&self) -> trc::Result<ClaudeTokens> {
        let mut state = REFRESH_STATE.lock().await;
        let current = self.anthropic_tokens().await?.ok_or_else(|| {
            trc::AuthEvent::Failed
                .into_err()
                .details("No Anthropic tokens stored, please log in first")
        })?;

        let tokens = refresh(&current).await.map_err(|err| {
            trc::AuthEvent::Error
                .into_err()
                .details("Anthropic token refresh failed")
                .reason(err)
        })?;

        self.persist_anthropic_tokens(tokens.clone()).await?;
        *state = RefreshState::default();
        Ok(tokens)
    }

    /// Returns a usable OAuth access token, refreshing it when it is about to
    /// expire. Returns `None` when no tokens are stored or they cannot be
    /// refreshed; the failure is logged once rather than on every call.
    pub async fn anthropic_oauth_token(&self) -> Option<String> {
        let tokens = self.anthropic_access_tokens().await?;
        let now = now();
        if tokens.is_fresh(now) {
            return Some(tokens.access_token);
        }

        let mut state = REFRESH_STATE.lock().await;

        // Another task may have refreshed while we waited for the lock.
        let tokens = self.anthropic_access_tokens().await?;
        if tokens.is_fresh(now) {
            return Some(tokens.access_token);
        }
        let still_valid = (tokens.expires_at > now).then(|| tokens.access_token.clone());

        let refresh_token = tokens.refresh_token.as_ref()?;
        if state.rejected_refresh_token.as_ref() == Some(refresh_token) || state.retry_after > now {
            return still_valid;
        }

        trc::event!(
            Ai(AiEvent::LlmResponse),
            Details = "Refreshing Anthropic OAuth token",
        );

        match refresh(&tokens).await {
            Ok(new_tokens) => {
                let access_token = new_tokens.access_token.clone();
                if let Err(err) = self.persist_anthropic_tokens(new_tokens).await {
                    // The refresh token may have been rotated; without persisting
                    // it the next refresh will fail.
                    trc::error!(err.details("Failed to persist refreshed Anthropic tokens"));
                }
                *state = RefreshState::default();
                Some(access_token)
            }
            Err(err) => {
                let permanent = err.is_permanent();
                if permanent {
                    state.rejected_refresh_token = Some(refresh_token.clone());
                } else {
                    state.retry_after = now + TRANSIENT_RETRY_SECS;
                }
                trc::event!(
                    Ai(AiEvent::ApiError),
                    Details = if permanent {
                        "Anthropic OAuth refresh token rejected, log in again from the admin UI"
                    } else {
                        "Anthropic OAuth token refresh failed, will retry"
                    },
                    Reason = err.to_string(),
                );
                still_valid
            }
        }
    }

    async fn anthropic_access_tokens(&self) -> Option<ClaudeTokens> {
        match self.anthropic_tokens().await {
            Ok(tokens) => tokens,
            Err(err) => {
                trc::error!(err.details("Failed to read stored Anthropic OAuth tokens"));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(json: &str) -> TokenResponse {
        serde_json::from_str(json).unwrap()
    }

    fn stored() -> ClaudeTokens {
        ClaudeTokens {
            access_token: "old-access".into(),
            refresh_token: Some("old-refresh".into()),
            expires_at: 1,
            scopes: vec!["user:inference".into()],
            account_email: Some("user@example.com".into()),
            organization_name: Some("Org".into()),
        }
    }

    #[test]
    fn refresh_response_keeps_previous_fields() {
        let tokens = ClaudeTokens::from_response(
            response(r#"{"access_token":"new-access","expires_in":100}"#),
            Some(&stored()),
            1000,
        );
        assert_eq!(tokens.access_token, "new-access");
        assert_eq!(tokens.refresh_token.as_deref(), Some("old-refresh"));
        assert_eq!(tokens.expires_at, 1100);
        assert_eq!(tokens.scopes, vec!["user:inference".to_string()]);
        assert_eq!(tokens.account_email.as_deref(), Some("user@example.com"));
        assert_eq!(tokens.organization_name.as_deref(), Some("Org"));
    }

    #[test]
    fn refresh_response_rotates_refresh_token() {
        let tokens = ClaudeTokens::from_response(
            response(r#"{"access_token":"a","refresh_token":"new-refresh","scope":"x y"}"#),
            Some(&stored()),
            0,
        );
        assert_eq!(tokens.refresh_token.as_deref(), Some("new-refresh"));
        assert_eq!(tokens.scopes, vec!["x".to_string(), "y".to_string()]);
        assert_eq!(tokens.expires_at, DEFAULT_EXPIRES_IN_SECS);
    }

    #[test]
    fn freshness_honours_buffer() {
        let mut tokens = stored();
        tokens.expires_at = 1000 + REFRESH_BUFFER_SECS;
        assert!(!tokens.is_fresh(1000));
        tokens.expires_at += 1;
        assert!(tokens.is_fresh(1000));
    }

    #[test]
    fn permanent_errors() {
        let rejected = |status| TokenError::Rejected {
            status,
            body: String::new(),
        };
        assert!(rejected(400).is_permanent());
        assert!(rejected(401).is_permanent());
        assert!(!rejected(429).is_permanent());
        assert!(!rejected(503).is_permanent());
        assert!(!TokenError::Network("timeout".into()).is_permanent());
    }
}

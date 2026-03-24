/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Server, auth::AccessToken};
use directory::Permission;
use http_proto::*;
use hyper::Method;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc, time::Duration};
use store::{
    Serialize as StoreSerialize,
    dispatch::lookup::KeyValue,
    write::{AlignedBytes, Archive, Archiver},
};
use trc::AddContext;

const CLAUDE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CLAUDE_AUTH_URL: &str = "https://claude.ai/oauth/authorize";
const CLAUDE_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
const CLAUDE_HOSTED_CALLBACK_URI: &str = "https://platform.claude.com/oauth/code/callback";

const DEFAULT_SCOPES: &[&str] = &[
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
];

const USER_AGENT: &str = "stalwart-mail/1.0.0 (external, cli)";
const VERIFIER_RANDOM_BYTES: usize = 32;
const PKCE_STATE_EXPIRY_SECS: u64 = 600;

const KV_ANTHROPIC_PKCE: u8 = 0x70;
const KV_ANTHROPIC_TOKENS: u8 = 0x71;

#[derive(Debug, Clone)]
pub struct PkceChallenge {
    pub verifier: String,
    pub challenge: String,
}

impl PkceChallenge {
    pub fn generate() -> Self {
        let verifier = Self::generate_verifier();
        let challenge = Self::compute_challenge(&verifier);
        Self { verifier, challenge }
    }

    fn generate_verifier() -> String {
        let mut random_bytes = [0u8; VERIFIER_RANDOM_BYTES];
        rand::rng().fill_bytes(&mut random_bytes);
        URL_SAFE_NO_PAD.encode(random_bytes)
    }

    fn compute_challenge(verifier: &str) -> String {
        let digest = Sha256::digest(verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }

    pub fn challenge_method() -> &'static str {
        "S256"
    }
}

#[derive(
    Debug, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Clone, Serialize, Deserialize,
)]
pub struct PkceState {
    pub verifier: String,
    pub account_id: u32,
}

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
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
    account: Option<AccountInfo>,
    organization: Option<OrganizationInfo>,
}

#[derive(Debug, Deserialize)]
struct AccountInfo {
    email_address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OrganizationInfo {
    name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub url: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct ExchangeResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenStatusResponse {
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

pub trait AnthropicOAuthHandler: Sync + Send {
    fn handle_anthropic_login(
        &self,
        access_token: Arc<AccessToken>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_anthropic_exchange(
        &self,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_anthropic_refresh(
        &self,
        access_token: Arc<AccessToken>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_anthropic_status(
        &self,
        access_token: Arc<AccessToken>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_anthropic_logout(
        &self,
        access_token: Arc<AccessToken>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_anthropic_oauth(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn get_anthropic_tokens(&self) -> impl Future<Output = trc::Result<Option<ClaudeTokens>>> + Send;
}

impl AnthropicOAuthHandler for Server {
    async fn handle_anthropic_oauth(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> trc::Result<HttpResponse> {
        access_token.assert_has_permission(Permission::SettingsUpdate)?;

        match (path.get(2).copied().unwrap_or_default(), req.method()) {
            ("login", &Method::GET) => self.handle_anthropic_login(access_token).await,
            ("exchange", &Method::POST) => {
                self.handle_anthropic_exchange(access_token, body).await
            }
            ("refresh", &Method::POST) => self.handle_anthropic_refresh(access_token).await,
            ("status", &Method::GET) => self.handle_anthropic_status(access_token).await,
            ("logout", &Method::DELETE) => self.handle_anthropic_logout(access_token).await,
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    async fn handle_anthropic_login(
        &self,
        access_token: Arc<AccessToken>,
    ) -> trc::Result<HttpResponse> {
        let pkce = PkceChallenge::generate();

        let params = [
            ("code", "true"),
            ("client_id", CLAUDE_CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", CLAUDE_HOSTED_CALLBACK_URI),
            ("scope", &DEFAULT_SCOPES.join(" ")),
            ("code_challenge", &pkce.challenge),
            ("code_challenge_method", PkceChallenge::challenge_method()),
            ("state", &pkce.verifier),
        ];

        let auth_url = format!(
            "{}?{}",
            CLAUDE_AUTH_URL,
            serde_urlencoded::to_string(&params).unwrap_or_default()
        );

        let state = PkceState {
            verifier: pkce.verifier.clone(),
            account_id: access_token.primary_id(),
        };

        let state_bytes = Archiver::new(state).untrusted().serialize().caused_by(trc::location!())?;

        self.core
            .storage
            .lookup
            .key_set(
                KeyValue::with_prefix(KV_ANTHROPIC_PKCE, pkce.verifier.as_bytes(), state_bytes)
                    .expires(PKCE_STATE_EXPIRY_SECS),
            )
            .await?;

        Ok(JsonResponse::new(LoginResponse {
            url: auth_url,
            state: pkce.verifier,
        })
        .into_http_response())
    }

    async fn handle_anthropic_exchange(
        &self,
        _access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> trc::Result<HttpResponse> {
        let body = body.ok_or_else(|| {
            trc::ResourceEvent::BadParameters
                .into_err()
                .details("Missing request body")
        })?;

        let request: ExchangeRequest = serde_json::from_slice(&body).map_err(|err| {
            trc::ResourceEvent::BadParameters
                .into_err()
                .details(format!("Invalid JSON: {}", err))
        })?;

        let state_archive = self
            .core
            .storage
            .lookup
            .key_get::<Archive<AlignedBytes>>(KeyValue::<()>::build_key(
                KV_ANTHROPIC_PKCE,
                request.state.as_bytes(),
            ))
            .await?
            .ok_or_else(|| {
                trc::AuthEvent::Failed
                    .into_err()
                    .details("Invalid or expired state. Please restart the login flow.")
            })?;

        let pkce_state = state_archive
            .unarchive::<PkceState>()
            .caused_by(trc::location!())?;

        self.core
            .storage
            .lookup
            .key_delete(KeyValue::<()>::build_key(
                KV_ANTHROPIC_PKCE,
                request.state.as_bytes(),
            ))
            .await?;

        let tokens = exchange_anthropic_code(&request.code, &pkce_state.verifier, &request.state)
            .await
            .map_err(|err| {
                trc::AuthEvent::Error
                    .into_err()
                    .details(format!("Token exchange failed: {}", err))
            })?;

        let account_email = tokens.account_email.clone();

        let tokens_bytes = Archiver::new(tokens)
            .untrusted()
            .serialize()
            .caused_by(trc::location!())?;

        self.core
            .storage
            .lookup
            .key_set(KeyValue::with_prefix(
                KV_ANTHROPIC_TOKENS,
                b"global",
                tokens_bytes,
            ))
            .await?;

        Ok(JsonResponse::new(ExchangeResponse {
            success: true,
            message: "Successfully authenticated with Claude".to_string(),
            account_email,
        })
        .into_http_response())
    }

    async fn handle_anthropic_refresh(
        &self,
        _access_token: Arc<AccessToken>,
    ) -> trc::Result<HttpResponse> {
        let current_tokens = self.get_anthropic_tokens().await?.ok_or_else(|| {
            trc::AuthEvent::Failed
                .into_err()
                .details("No tokens stored. Please authenticate first.")
        })?;

        let refresh_token = current_tokens.refresh_token.as_ref().ok_or_else(|| {
            trc::AuthEvent::Failed
                .into_err()
                .details("No refresh token available")
        })?;

        let new_tokens = refresh_anthropic_tokens(refresh_token).await.map_err(|err| {
            trc::AuthEvent::Error
                .into_err()
                .details(format!("Token refresh failed: {}", err))
        })?;

        let account_email = new_tokens.account_email.clone();

        let tokens_bytes = Archiver::new(new_tokens)
            .untrusted()
            .serialize()
            .caused_by(trc::location!())?;

        self.core
            .storage
            .lookup
            .key_set(KeyValue::with_prefix(
                KV_ANTHROPIC_TOKENS,
                b"global",
                tokens_bytes,
            ))
            .await?;

        Ok(JsonResponse::new(ExchangeResponse {
            success: true,
            message: "Tokens refreshed successfully".to_string(),
            account_email,
        })
        .into_http_response())
    }

    async fn handle_anthropic_status(
        &self,
        _access_token: Arc<AccessToken>,
    ) -> trc::Result<HttpResponse> {
        let response = match self.get_anthropic_tokens().await? {
            Some(tokens) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                TokenStatusResponse {
                    authenticated: tokens.expires_at > now,
                    account_email: tokens.account_email,
                    organization: tokens.organization_name,
                    expires_at: Some(tokens.expires_at),
                }
            }
            None => TokenStatusResponse {
                authenticated: false,
                account_email: None,
                organization: None,
                expires_at: None,
            },
        };

        Ok(JsonResponse::new(response).into_http_response())
    }

    async fn handle_anthropic_logout(
        &self,
        _access_token: Arc<AccessToken>,
    ) -> trc::Result<HttpResponse> {
        self.core
            .storage
            .lookup
            .key_delete(KeyValue::<()>::build_key(KV_ANTHROPIC_TOKENS, b"global"))
            .await?;

        Ok(JsonResponse::new(ExchangeResponse {
            success: true,
            message: "Logged out from Claude".to_string(),
            account_email: None,
        })
        .into_http_response())
    }

    async fn get_anthropic_tokens(&self) -> trc::Result<Option<ClaudeTokens>> {
        match self
            .core
            .storage
            .lookup
            .key_get::<Archive<AlignedBytes>>(KeyValue::<()>::build_key(
                KV_ANTHROPIC_TOKENS,
                b"global",
            ))
            .await?
        {
            Some(archive) => {
                let tokens = archive
                    .deserialize::<ClaudeTokens>()
                    .caused_by(trc::location!())?;
                Ok(Some(tokens))
            }
            None => Ok(None),
        }
    }
}

async fn exchange_anthropic_code(
    code: &str,
    code_verifier: &str,
    state: &str,
) -> Result<ClaudeTokens, String> {
    let body = serde_json::json!({
        "code": code,
        "state": state,
        "grant_type": "authorization_code",
        "client_id": CLAUDE_CLIENT_ID,
        "redirect_uri": CLAUDE_HOSTED_CALLBACK_URI,
        "code_verifier": code_verifier,
    });

    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| format!("Failed to create HTTP client: {}", err))?
        .post(CLAUDE_TOKEN_URL)
        .header("Content-Type", "application/json")
        .header("User-Agent", USER_AGENT)
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("Token request failed: {}", err))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Token endpoint returned {}: {}",
            status.as_u16(),
            body
        ));
    }

    let token_response: TokenResponse = response
        .json()
        .await
        .map_err(|err| format!("Failed to parse token response: {}", err))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let expires_in = token_response.expires_in.unwrap_or(28800);
    let scopes = token_response
        .scope
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    Ok(ClaudeTokens {
        access_token: token_response.access_token,
        refresh_token: token_response.refresh_token,
        expires_at: now + expires_in,
        scopes,
        account_email: token_response.account.and_then(|a| a.email_address),
        organization_name: token_response.organization.and_then(|o| o.name),
    })
}

async fn refresh_anthropic_tokens(refresh_token: &str) -> Result<ClaudeTokens, String> {
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLAUDE_CLIENT_ID,
        "scope": DEFAULT_SCOPES.join(" "),
    });

    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| format!("Failed to create HTTP client: {}", err))?
        .post(CLAUDE_TOKEN_URL)
        .header("Content-Type", "application/json")
        .header("User-Agent", USER_AGENT)
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("Refresh request failed: {}", err))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Token refresh returned {}: {}",
            status.as_u16(),
            body
        ));
    }

    let token_response: TokenResponse = response
        .json()
        .await
        .map_err(|err| format!("Failed to parse refresh response: {}", err))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let expires_in = token_response.expires_in.unwrap_or(28800);
    let scopes = token_response
        .scope
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    Ok(ClaudeTokens {
        access_token: token_response.access_token,
        refresh_token: token_response.refresh_token,
        expires_at: now + expires_in,
        scopes,
        account_email: token_response.account.and_then(|a| a.email_address),
        organization_name: token_response.organization.and_then(|o| o.name),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // PKCE Challenge Tests
    // =============================================================================

    #[test]
    fn test_pkce_verifier_length() {
        let pkce = PkceChallenge::generate();
        // Base64 encoding of 32 bytes = 43 characters (URL_SAFE_NO_PAD)
        assert_eq!(pkce.verifier.len(), 43, "PKCE verifier should be 43 chars (base64 of 32 bytes)");
    }

    #[test]
    fn test_pkce_challenge_is_sha256_of_verifier() {
        let pkce = PkceChallenge::generate();
        
        // Manually compute the challenge from verifier
        let expected_challenge = {
            let digest = Sha256::digest(pkce.verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        };
        
        assert_eq!(pkce.challenge, expected_challenge, "Challenge should be SHA256 of verifier");
    }

    #[test]
    fn test_pkce_uniqueness() {
        let pkce1 = PkceChallenge::generate();
        let pkce2 = PkceChallenge::generate();
        
        assert_ne!(pkce1.verifier, pkce2.verifier, "Each PKCE should have unique verifier");
        assert_ne!(pkce1.challenge, pkce2.challenge, "Each PKCE should have unique challenge");
    }

    #[test]
    fn test_pkce_challenge_method() {
        assert_eq!(PkceChallenge::challenge_method(), "S256", "Challenge method should be S256");
    }

    #[test]
    fn test_pkce_verifier_is_url_safe() {
        let pkce = PkceChallenge::generate();
        
        // URL-safe base64 should only contain these characters
        let valid_chars: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        
        for c in pkce.verifier.chars() {
            assert!(valid_chars.contains(c), "Verifier should be URL-safe base64, found '{}'", c);
        }
    }

    // =============================================================================
    // OAuth URL Construction Tests
    // =============================================================================

    #[test]
    fn test_auth_url_format() {
        let pkce = PkceChallenge::generate();
        
        let params = [
            ("code", "true"),
            ("client_id", CLAUDE_CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", CLAUDE_HOSTED_CALLBACK_URI),
            ("scope", &DEFAULT_SCOPES.join(" ")),
            ("code_challenge", &pkce.challenge),
            ("code_challenge_method", PkceChallenge::challenge_method()),
            ("state", &pkce.verifier),
        ];

        let auth_url = format!(
            "{}?{}",
            CLAUDE_AUTH_URL,
            serde_urlencoded::to_string(&params).unwrap_or_default()
        );

        // Verify URL starts with correct base
        assert!(auth_url.starts_with("https://claude.ai/oauth/authorize?"), 
            "Auth URL should use claude.ai, got: {}", auth_url);
        
        // Verify required params are present
        assert!(auth_url.contains("client_id="), "URL should contain client_id");
        assert!(auth_url.contains("response_type=code"), "URL should contain response_type=code");
        assert!(auth_url.contains("code_challenge="), "URL should contain code_challenge");
        assert!(auth_url.contains("code_challenge_method=S256"), "URL should contain S256 method");
        assert!(auth_url.contains("redirect_uri="), "URL should contain redirect_uri");
    }

    #[test]
    fn test_claude_constants() {
        assert_eq!(CLAUDE_CLIENT_ID, "9d1c250a-e61b-44d9-88ed-5944d1962f5e");
        assert_eq!(CLAUDE_AUTH_URL, "https://claude.ai/oauth/authorize");
        assert_eq!(CLAUDE_TOKEN_URL, "https://platform.claude.com/v1/oauth/token");
        assert_eq!(CLAUDE_HOSTED_CALLBACK_URI, "https://platform.claude.com/oauth/code/callback");
    }

    #[test]
    fn test_default_scopes() {
        let scopes = DEFAULT_SCOPES;
        
        assert!(scopes.contains(&"user:profile"), "Should include user:profile scope");
        assert!(scopes.contains(&"user:inference"), "Should include user:inference scope");
        assert!(scopes.len() >= 2, "Should have at least 2 scopes");
    }

    // =============================================================================
    // Token Structure Tests
    // =============================================================================

    #[test]
    fn test_claude_tokens_serialization_json() {
        let tokens = ClaudeTokens {
            access_token: "sk-ant-oat-test-token-12345".to_string(),
            refresh_token: Some("refresh-token-xyz".to_string()),
            expires_at: 1700000000,
            scopes: vec!["user:profile".to_string(), "user:inference".to_string()],
            account_email: Some("test@example.com".to_string()),
            organization_name: Some("Test Org".to_string()),
        };

        // Test JSON roundtrip
        let json = serde_json::to_string(&tokens).expect("Should serialize to JSON");
        let parsed: ClaudeTokens = serde_json::from_str(&json).expect("Should deserialize from JSON");
        
        assert_eq!(parsed.access_token, tokens.access_token);
        assert_eq!(parsed.refresh_token, tokens.refresh_token);
        assert_eq!(parsed.expires_at, tokens.expires_at);
        assert_eq!(parsed.scopes, tokens.scopes);
        assert_eq!(parsed.account_email, tokens.account_email);
        assert_eq!(parsed.organization_name, tokens.organization_name);
    }

    #[test]
    fn test_claude_tokens_without_optional_fields() {
        let tokens = ClaudeTokens {
            access_token: "sk-ant-oat-minimal".to_string(),
            refresh_token: None,
            expires_at: 1700000000,
            scopes: vec![],
            account_email: None,
            organization_name: None,
        };

        let json = serde_json::to_string(&tokens).expect("Should serialize minimal tokens");
        let parsed: ClaudeTokens = serde_json::from_str(&json).expect("Should deserialize minimal tokens");
        
        assert!(parsed.refresh_token.is_none());
        assert!(parsed.account_email.is_none());
        assert!(parsed.organization_name.is_none());
    }

    #[test]
    fn test_oauth_token_detection() {
        // OAuth tokens start with sk-ant-oat
        let oauth_token = "sk-ant-oat-abcd1234-xyz";
        let api_key = "sk-ant-api01-abcd1234-xyz";
        
        assert!(oauth_token.starts_with("sk-ant-oat"), "OAuth token should start with sk-ant-oat");
        assert!(!api_key.starts_with("sk-ant-oat"), "API key should NOT start with sk-ant-oat");
    }

    // =============================================================================
    // Request/Response Structure Tests
    // =============================================================================

    #[test]
    fn test_exchange_request_deserialization() {
        let json = r#"{"code": "auth-code-123", "state": "verifier-state-xyz"}"#;
        let request: ExchangeRequest = serde_json::from_str(json).expect("Should parse ExchangeRequest");
        
        assert_eq!(request.code, "auth-code-123");
        assert_eq!(request.state, "verifier-state-xyz");
    }

    #[test]
    fn test_login_response_serialization() {
        let response = LoginResponse {
            url: "https://claude.ai/oauth/authorize?foo=bar".to_string(),
            state: "test-state-123".to_string(),
        };

        let json = serde_json::to_string(&response).expect("Should serialize LoginResponse");
        
        assert!(json.contains("\"url\":"));
        assert!(json.contains("\"state\":"));
        assert!(json.contains("test-state-123"));
    }

    #[test]
    fn test_token_status_response() {
        // Authenticated response
        let auth_response = TokenStatusResponse {
            authenticated: true,
            account_email: Some("user@example.com".to_string()),
            organization: Some("My Org".to_string()),
            expires_at: Some(1700000000),
        };

        let json = serde_json::to_string(&auth_response).expect("Should serialize");
        assert!(json.contains("\"authenticated\":true"));
        assert!(json.contains("\"account_email\":"));

        // Unauthenticated response (None fields should be skipped)
        let unauth_response = TokenStatusResponse {
            authenticated: false,
            account_email: None,
            organization: None,
            expires_at: None,
        };

        let json = serde_json::to_string(&unauth_response).expect("Should serialize");
        assert!(json.contains("\"authenticated\":false"));
        // With skip_serializing_if, None fields should not appear
        assert!(!json.contains("account_email"), "None fields should be skipped");
    }

    // =============================================================================
    // PKCE State Tests
    // =============================================================================

    #[test]
    fn test_pkce_state_structure() {
        let state = PkceState {
            verifier: "test-verifier-12345".to_string(),
            account_id: 42,
        };

        assert_eq!(state.verifier, "test-verifier-12345");
        assert_eq!(state.account_id, 42);
    }

    // =============================================================================
    // Token Response Parsing Tests
    // =============================================================================

    #[test]
    fn test_token_response_parsing_full() {
        let json = r#"{
            "access_token": "sk-ant-oat-test",
            "refresh_token": "refresh-123",
            "expires_in": 3600,
            "scope": "user:profile user:inference",
            "account": {"email_address": "user@example.com"},
            "organization": {"name": "Test Org"}
        }"#;

        let response: TokenResponse = serde_json::from_str(json).expect("Should parse full response");
        
        assert_eq!(response.access_token, "sk-ant-oat-test");
        assert_eq!(response.refresh_token, Some("refresh-123".to_string()));
        assert_eq!(response.expires_in, Some(3600));
        assert_eq!(response.scope, Some("user:profile user:inference".to_string()));
        assert!(response.account.is_some());
        assert!(response.organization.is_some());
    }

    #[test]
    fn test_token_response_parsing_minimal() {
        let json = r#"{"access_token": "sk-ant-oat-minimal"}"#;

        let response: TokenResponse = serde_json::from_str(json).expect("Should parse minimal response");
        
        assert_eq!(response.access_token, "sk-ant-oat-minimal");
        assert!(response.refresh_token.is_none());
        assert!(response.expires_in.is_none());
        assert!(response.scope.is_none());
        assert!(response.account.is_none());
        assert!(response.organization.is_none());
    }

    // =============================================================================
    // Integration-Style Tests (no network)
    // =============================================================================

    #[test]
    fn test_scope_string_parsing() {
        let scope_str = "user:profile user:inference user:sessions:claude_code";
        let scopes: Vec<String> = scope_str.split_whitespace().map(String::from).collect();
        
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&"user:profile".to_string()));
        assert!(scopes.contains(&"user:inference".to_string()));
    }

    #[test]
    fn test_expires_at_calculation() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let expires_in: u64 = 3600; // 1 hour
        let expires_at = now + expires_in;
        
        // Should be in the future
        assert!(expires_at > now);
        // Should be approximately 1 hour from now
        assert!((expires_at - now) >= 3599 && (expires_at - now) <= 3601);
    }

    #[test]
    fn test_token_expiry_check() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Token that expires in the future
        let future_token = ClaudeTokens {
            access_token: "future".to_string(),
            refresh_token: None,
            expires_at: now + 3600, // 1 hour from now
            scopes: vec![],
            account_email: None,
            organization_name: None,
        };
        assert!(future_token.expires_at > now, "Future token should not be expired");

        // Token that expired in the past
        let past_token = ClaudeTokens {
            access_token: "expired".to_string(),
            refresh_token: None,
            expires_at: now - 3600, // 1 hour ago
            scopes: vec![],
            account_email: None,
            organization_name: None,
        };
        assert!(past_token.expires_at <= now, "Past token should be expired");
    }

    // =============================================================================
    // rkyv Serialization Tests (for storage)
    // =============================================================================

    #[test]
    fn test_pkce_state_rkyv_serialization() {
        use store::write::Archiver;

        let state = PkceState {
            verifier: "test-verifier-for-rkyv".to_string(),
            account_id: 123,
        };

        let bytes = Archiver::new(state)
            .untrusted()
            .serialize()
            .expect("Should serialize PkceState with rkyv");

        assert!(!bytes.is_empty(), "Serialized bytes should not be empty");
        assert!(bytes.len() > 10, "Serialized bytes should have content");
    }

    #[test]
    fn test_claude_tokens_rkyv_serialization() {
        use store::write::Archiver;

        let tokens = ClaudeTokens {
            access_token: "sk-ant-oat-rkyv-test".to_string(),
            refresh_token: Some("refresh-rkyv".to_string()),
            expires_at: 1700000000,
            scopes: vec!["user:profile".to_string(), "user:inference".to_string()],
            account_email: Some("rkyv@test.com".to_string()),
            organization_name: Some("rkyv Org".to_string()),
        };

        let bytes = Archiver::new(tokens)
            .untrusted()
            .serialize()
            .expect("Should serialize ClaudeTokens with rkyv");

        assert!(!bytes.is_empty(), "Serialized bytes should not be empty");
        assert!(bytes.len() > 50, "Serialized bytes should have substantial content");
    }

    #[test]
    fn test_claude_tokens_minimal_rkyv_serialization() {
        use store::write::Archiver;

        let tokens = ClaudeTokens {
            access_token: "sk-ant-oat-minimal".to_string(),
            refresh_token: None,
            expires_at: 1700000000,
            scopes: vec![],
            account_email: None,
            organization_name: None,
        };

        let bytes = Archiver::new(tokens)
            .untrusted()
            .serialize()
            .expect("Should serialize minimal ClaudeTokens with rkyv");

        assert!(!bytes.is_empty(), "Serialized bytes should not be empty");
    }
}

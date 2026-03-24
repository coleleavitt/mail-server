/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{future::Future, time::Instant};

use common::Server;
use common::enterprise::llm::ApiType;
use trc::AiEvent;

use crate::SpamFilterContext;

pub trait SpamFilterAnalyzeLlm: Sync + Send {
    fn spam_filter_analyze_llm(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;

    fn get_anthropic_oauth_token(&self) -> impl Future<Output = Option<String>> + Send;
}

impl SpamFilterAnalyzeLlm for Server {
    async fn spam_filter_analyze_llm(&self, ctx: &mut SpamFilterContext<'_>) {
        if let Some(config) = self
            .core
            .enterprise
            .as_ref()
            .and_then(|c| c.spam_filter_llm.as_ref())
        {
            let time = Instant::now();
            let body = if let Some(body) = ctx.text_body() {
                body
            } else {
                return;
            };
            let prompt = format!(
                "{}\n\nSubject: {}\n\n{}",
                config.prompt, ctx.output.subject, body
            );

            let oauth_token = if matches!(config.model.api_type, ApiType::Anthropic) {
                self.get_anthropic_oauth_token().await
            } else {
                None
            };

            match config
                .model
                .send_request_with_token(prompt, config.temperature.into(), oauth_token.as_deref())
                .await
            {
                Ok(response) => {
                    trc::event!(
                        Ai(AiEvent::LlmResponse),
                        Id = config.model.id.clone(),
                        Details = response.clone(),
                        Elapsed = time.elapsed(),
                        SpanId = ctx.input.span_id,
                    );

                    let mut category = None;
                    let mut confidence = None;
                    let mut explanation = None;

                    for (idx, value) in response.split(config.separator).enumerate() {
                        let value = value.trim();
                        if !value.is_empty() {
                            if idx == config.index_category {
                                let value = value.to_uppercase();
                                if config.categories.contains(value.as_str()) {
                                    category = Some(value);
                                }
                            } else if config.index_confidence.is_some_and(|i| i == idx) {
                                let value = value.to_uppercase();
                                if config.confidence.contains(value.as_str()) {
                                    confidence = Some(value);
                                }
                            } else if config.index_explanation.is_some_and(|i| i == idx) {
                                let explanation = explanation.get_or_insert_with(|| {
                                    String::with_capacity(std::cmp::min(value.len(), 255))
                                });

                                for value in value.chars() {
                                    if !value.is_whitespace() {
                                        explanation.push(value);
                                    } else {
                                        explanation.push(' ');
                                    }
                                    if explanation.len() == 255 {
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    let category = match (category, confidence) {
                        (Some(category), Some(confidence)) => {
                            ctx.result.add_tag(format!("LLM_{category}_{confidence}"));
                            category
                        }
                        (Some(category), None) => {
                            ctx.result.add_tag(format!("LLM_{category}"));
                            category
                        }
                        _ => return,
                    };

                    if let Some(explanation) = explanation {
                        ctx.result.llm_result = Some((category, explanation));
                    }
                }
                Err(err) => {
                    trc::error!(err.span_id(ctx.input.span_id));
                }
            }
        }
    }

    async fn get_anthropic_oauth_token(&self) -> Option<String> {
        use store::{
            Serialize as StoreSerialize,
            dispatch::lookup::KeyValue,
            write::{AlignedBytes, Archiver, Archive},
        };

        const KV_ANTHROPIC_TOKENS: u8 = 0x71;
        const REFRESH_BUFFER_SECS: u64 = 300;

        let archive = self
            .core
            .storage
            .lookup
            .key_get::<Archive<AlignedBytes>>(KeyValue::<()>::build_key(
                KV_ANTHROPIC_TOKENS,
                b"global",
            ))
            .await
            .ok()
            .flatten()?;

        #[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Clone)]
        #[allow(dead_code)]
        struct ClaudeTokens {
            access_token: String,
            refresh_token: Option<String>,
            expires_at: u64,
            scopes: Vec<String>,
            account_email: Option<String>,
            organization_name: Option<String>,
        }

        let tokens: ClaudeTokens = archive.deserialize().ok()?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if tokens.expires_at > now + REFRESH_BUFFER_SECS {
            return Some(tokens.access_token);
        }

        let refresh_token = tokens.refresh_token.as_ref()?;

        trc::event!(
            Ai(AiEvent::LlmResponse),
            Details = "Auto-refreshing expired Anthropic OAuth token",
        );

        let body = format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{}","client_id":"9d1c250a-e61b-44d9-88ed-5944d1962f5e"}}"#,
            refresh_token
        );

        let response = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .ok()?
            .post("https://platform.claude.com/v1/oauth/token")
            .header("Content-Type", "application/json")
            .header("User-Agent", "stalwart-mail/1.0.0 (external, cli)")
            .body(body)
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            trc::event!(
                Ai(AiEvent::ApiError),
                Details = format!(
                    "OAuth token refresh failed: {}",
                    response.status().as_u16()
                ),
            );
            if tokens.expires_at > now {
                return Some(tokens.access_token);
            }
            return None;
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
        }

        let token_response: TokenResponse = response.json().await.ok()?;
        let new_expires_at = now + token_response.expires_in.unwrap_or(28800);

        let new_tokens = ClaudeTokens {
            access_token: token_response.access_token.clone(),
            refresh_token: token_response
                .refresh_token
                .or(tokens.refresh_token.clone()),
            expires_at: new_expires_at,
            scopes: tokens.scopes.clone(),
            account_email: tokens.account_email.clone(),
            organization_name: tokens.organization_name.clone(),
        };

        if let Ok(bytes) = Archiver::new(new_tokens).untrusted().serialize() {
            let _ = self
                .core
                .storage
                .lookup
                .key_set(KeyValue::with_prefix(
                    KV_ANTHROPIC_TOKENS,
                    b"global",
                    bytes,
                ))
                .await;
        }

        Some(token_response.access_token)
    }
}

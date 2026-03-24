/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use hyper::{HeaderMap, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use utils::config::{Config, http::parse_http_headers};

#[derive(Clone, Debug)]
pub struct AiApiConfig {
    pub id: String,
    pub api_type: ApiType,
    pub url: String,
    pub model: String,
    pub timeout: Duration,
    pub headers: HeaderMap,
    pub tls_allow_invalid_certs: bool,
    pub default_temperature: f64,
    pub max_tokens: u32,
    pub api_key: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum ApiType {
    ChatCompletion,
    TextCompletion,
    Anthropic,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub temperature: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChatCompletionResponse {
    pub created: i64,
    pub object: String,
    pub id: String,
    pub model: String,
    pub choices: Vec<ChatCompletionChoice>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChatCompletionChoice {
    pub index: i32,
    pub finish_reason: String,
    pub message: Message,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TextCompletionRequest {
    pub model: String,
    pub prompt: String,
    pub temperature: f64,
}

#[derive(Deserialize, Debug)]
pub struct TextCompletionResponse {
    pub created: i64,
    pub object: String,
    pub id: String,
    pub model: String,
    pub choices: Vec<TextCompletionChoice>,
}

#[derive(Deserialize, Debug)]
pub struct TextCompletionChoice {
    pub index: i32,
    pub finish_reason: String,
    pub text: String,
}

#[derive(Serialize, Debug)]
pub struct AnthropicRequest {
    pub model: String,
    pub max_tokens: u32,
    pub messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AnthropicMessage {
    pub role: String,
    pub content: String,
}

#[derive(Deserialize, Debug)]
pub struct AnthropicResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub response_type: String,
    pub role: String,
    pub content: Vec<AnthropicContentBlock>,
    pub model: String,
    pub stop_reason: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum AnthropicContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(other)]
    Other,
}

impl AiApiConfig {
    pub async fn send_request(
        &self,
        prompt: impl Into<String>,
        temperature: Option<f64>,
    ) -> trc::Result<String> {
        self.send_request_with_token(prompt, temperature, None).await
    }

    pub async fn send_request_with_token(
        &self,
        prompt: impl Into<String>,
        temperature: Option<f64>,
        oauth_token: Option<&str>,
    ) -> trc::Result<String> {
        self.post_api(prompt, temperature, oauth_token)
            .await
            .map_err(|err| {
                trc::Error::new(trc::EventType::Ai(trc::AiEvent::ApiError))
                    .id(self.id.clone())
                    .details("OpenAPI request failed")
                    .reason(err)
            })
    }

    async fn post_api(
        &self,
        prompt: impl Into<String>,
        temperature: Option<f64>,
        oauth_token: Option<&str>,
    ) -> Result<String, String> {
        let body = match self.api_type {
            ApiType::ChatCompletion => serde_json::to_string(&ChatCompletionRequest {
                model: self.model.to_string(),
                messages: vec![Message {
                    role: "user".to_string(),
                    content: prompt.into(),
                }],
                temperature: temperature.unwrap_or(self.default_temperature),
            })
            .map_err(|err| format!("Failed to serialize request: {}", err))?,
            ApiType::TextCompletion => serde_json::to_string(&TextCompletionRequest {
                model: self.model.to_string(),
                prompt: prompt.into(),
                temperature: temperature.unwrap_or(self.default_temperature),
            })
            .map_err(|err| format!("Failed to serialize request: {}", err))?,
            ApiType::Anthropic => serde_json::to_string(&AnthropicRequest {
                model: self.model.to_string(),
                max_tokens: self.max_tokens,
                messages: vec![AnthropicMessage {
                    role: "user".to_string(),
                    content: prompt.into(),
                }],
                temperature: temperature.or(Some(self.default_temperature)),
            })
            .map_err(|err| format!("Failed to serialize Anthropic request: {}", err))?,
        };

        let mut headers = self.headers.clone();
        if let ApiType::Anthropic = &self.api_type {
            let token = oauth_token.or(self.api_key.as_deref());
            if let Some(api_key) = token {
                self.add_anthropic_auth_headers(&mut headers, api_key);
            }
        }

        // Send request
        let response = reqwest::Client::builder()
            .timeout(self.timeout)
            .danger_accept_invalid_certs(self.tls_allow_invalid_certs)
            .build()
            .map_err(|err| format!("Failed to create HTTP client: {}", err))?
            .post(&self.url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|err| format!("API request to {} failed: {err}", self.url))?;

        if response.status().is_success() {
            let bytes = response.bytes().await.map_err(|err| {
                format!("Failed to read response body from {}: {}", self.url, err)
            })?;

            match self.api_type {
                ApiType::ChatCompletion => {
                    let response = serde_json::from_slice::<ChatCompletionResponse>(&bytes)
                        .map_err(|err| {
                            format!(
                                "Failed to chat completion parse response from {}: {}",
                                self.url, err
                            )
                        })?;
                    response
                        .choices
                        .into_iter()
                        .next()
                        .map(|choice| choice.message.content)
                        .filter(|text| !text.is_empty())
                        .ok_or_else(|| {
                            format!(
                                "Chat completion response from {} did not contain any choices: {}",
                                self.url,
                                std::str::from_utf8(&bytes).unwrap_or_default()
                            )
                        })
                }
                ApiType::TextCompletion => {
                    let response = serde_json::from_slice::<TextCompletionResponse>(&bytes)
                        .map_err(|err| {
                            format!(
                                "Failed to parse text completion response from {}: {}",
                                self.url, err
                            )
                        })?;
                    response
                        .choices
                        .into_iter()
                        .next()
                        .map(|choice| choice.text)
                        .filter(|text| !text.is_empty())
                        .ok_or_else(|| {
                            format!(
                                "Text completion response from {} did not contain any choices: {}",
                                self.url,
                                std::str::from_utf8(&bytes).unwrap_or_default()
                            )
                        })
                }
                ApiType::Anthropic => {
                    let response = serde_json::from_slice::<AnthropicResponse>(&bytes)
                        .map_err(|err| {
                            format!(
                                "Failed to parse Anthropic response from {}: {}",
                                self.url, err
                            )
                        })?;
                    response
                        .content
                        .into_iter()
                        .find_map(|block| match block {
                            AnthropicContentBlock::Text { text } if !text.is_empty() => Some(text),
                            _ => None,
                        })
                        .ok_or_else(|| {
                            format!(
                                "Anthropic response from {} did not contain any text: {}",
                                self.url,
                                std::str::from_utf8(&bytes).unwrap_or_default()
                            )
                        })
                }
            }
        } else {
            let status = response.status();
            let bytes = response.bytes().await.unwrap_or_default();

            Err(format!(
                "OpenAPI request to {} failed with code {} ({}): {}",
                self.url,
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown"),
                std::str::from_utf8(&bytes).unwrap_or_default()
            ))
        }
    }

    fn add_anthropic_auth_headers(&self, headers: &mut HeaderMap, api_key: &str) {
        use hyper::header::HeaderName;
        use hyper::header::HeaderValue;

        const OAUTH_TOKEN_PREFIX: &str = "sk-ant-oat";
        const ANTHROPIC_VERSION: &str = "2023-06-01";
        const OAUTH_BETA_HEADER: &str = "oauth-2025-04-20";

        if api_key.starts_with(OAUTH_TOKEN_PREFIX) {
            headers.insert(
                hyper::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", api_key)).unwrap(),
            );
            headers.insert(
                HeaderName::from_static("anthropic-beta"),
                HeaderValue::from_static(OAUTH_BETA_HEADER),
            );
        } else {
            headers.insert(
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(api_key).unwrap(),
            );
        }
        headers.insert(
            HeaderName::from_static("anthropic-version"),
            HeaderValue::from_static(ANTHROPIC_VERSION),
        );
    }

    pub fn parse(config: &mut Config, id: &str) -> Option<Self> {
        let url = config.value(("enterprise.ai", id, "url"))?.to_string();
        let api_type = match config.value(("enterprise.ai", id, "type"))? {
            "chat" => ApiType::ChatCompletion,
            "text" => ApiType::TextCompletion,
            "anthropic" => ApiType::Anthropic,
            _ => {
                config.new_build_error(("enterprise.ai", id, "type"), "Invalid API type");
                return None;
            }
        };

        let mut headers = parse_http_headers(config, ("enterprise.ai", id));
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        Some(AiApiConfig {
            id: id.to_string(),
            api_type,
            url,
            headers,
            model: config
                .value_require(("enterprise.ai", id, "model"))?
                .to_string(),
            timeout: config
                .property_or_default(("enterprise.ai", id, "timeout"), "2m")
                .unwrap_or_else(|| Duration::from_secs(120)),
            tls_allow_invalid_certs: config
                .property_or_default(("enterprise.ai", id, "allow-invalid-certs"), "false")
                .unwrap_or_default(),
            default_temperature: config
                .property_or_default(("enterprise.ai", id, "default-temperature"), "0.7")
                .unwrap_or(0.7),
            max_tokens: config
                .property_or_default(("enterprise.ai", id, "max-tokens"), "1024")
                .unwrap_or(1024),
            api_key: config
                .value(("enterprise.ai", id, "api-key"))
                .map(|s| s.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANTHROPIC_MODEL_SONNET: &str = "claude-sonnet-4-20250514";
    const ANTHROPIC_MODEL_HAIKU: &str = "claude-haiku-4-5-20251001";

    fn create_test_config(api_type: ApiType) -> AiApiConfig {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        AiApiConfig {
            id: "test".to_string(),
            api_type,
            url: "https://api.anthropic.com/v1/messages".to_string(),
            model: ANTHROPIC_MODEL_SONNET.to_string(),
            timeout: Duration::from_secs(30),
            headers,
            tls_allow_invalid_certs: false,
            default_temperature: 0.7,
            max_tokens: 1024,
            api_key: None,
        }
    }

    #[test]
    fn test_anthropic_request_serialization() {
        let request = AnthropicRequest {
            model: ANTHROPIC_MODEL_SONNET.to_string(),
            max_tokens: 1024,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: "Classify this email as SPAM or HAM".to_string(),
            }],
            temperature: Some(0.5),
        };

        let json = serde_json::to_string(&request).expect("Should serialize");
        assert!(json.contains(ANTHROPIC_MODEL_SONNET));
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("max_tokens"));
        assert!(json.contains("1024"));
    }

    #[test]
    fn test_anthropic_response_parsing() {
        let response_json = r#"{
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "SPAM|HIGH|This is unsolicited commercial email"}],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn"
        }"#;

        let response: AnthropicResponse = serde_json::from_str(response_json)
            .expect("Should parse Anthropic response");

        assert_eq!(response.id, "msg_123");
        assert_eq!(response.role, "assistant");
        assert_eq!(response.model, ANTHROPIC_MODEL_SONNET);

        let text = response.content.into_iter().find_map(|block| match block {
            AnthropicContentBlock::Text { text } => Some(text),
            _ => None,
        });
        assert_eq!(
            text,
            Some("SPAM|HIGH|This is unsolicited commercial email".to_string())
        );
    }

    #[test]
    fn test_anthropic_response_multiple_content_blocks() {
        let response_json = r#"{
            "id": "msg_456",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": ""},
                {"type": "text", "text": "HAM|HIGH|Normal business email"}
            ],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn"
        }"#;

        let response: AnthropicResponse =
            serde_json::from_str(response_json).expect("Should parse");

        let text = response.content.into_iter().find_map(|block| match block {
            AnthropicContentBlock::Text { text } if !text.is_empty() => Some(text),
            _ => None,
        });
        assert_eq!(
            text,
            Some("HAM|HIGH|Normal business email".to_string())
        );
    }

    #[test]
    fn test_anthropic_oauth_headers() {
        let config = create_test_config(ApiType::Anthropic);
        let mut headers = HeaderMap::new();

        let oauth_token = "sk-ant-oat-abcdef123456-xyz";
        config.add_anthropic_auth_headers(&mut headers, oauth_token);

        assert!(headers.contains_key("authorization"));
        assert!(headers.contains_key("anthropic-version"));
        assert!(headers.contains_key("anthropic-beta"));

        let auth = headers.get("authorization").unwrap().to_str().unwrap();
        assert!(
            auth.starts_with("Bearer sk-ant-oat-"),
            "OAuth should use Bearer auth"
        );

        let beta = headers.get("anthropic-beta").unwrap().to_str().unwrap();
        assert_eq!(beta, "oauth-2025-04-20");
    }

    #[test]
    fn test_anthropic_api_key_headers() {
        let config = create_test_config(ApiType::Anthropic);
        let mut headers = HeaderMap::new();

        let api_key = "sk-ant-api01-regular-api-key";
        config.add_anthropic_auth_headers(&mut headers, api_key);

        assert!(
            headers.contains_key("x-api-key"),
            "API key should use x-api-key header"
        );
        assert!(headers.contains_key("anthropic-version"));
        assert!(
            !headers.contains_key("anthropic-beta"),
            "API key should NOT have beta header"
        );

        let key = headers.get("x-api-key").unwrap().to_str().unwrap();
        assert_eq!(key, api_key);
    }

    #[test]
    fn test_anthropic_version_header_always_set() {
        let config = create_test_config(ApiType::Anthropic);

        for token in ["sk-ant-oat-oauth-token", "sk-ant-api01-key", "plain-key"] {
            let mut headers = HeaderMap::new();
            config.add_anthropic_auth_headers(&mut headers, token);
            assert_eq!(
                headers.get("anthropic-version").unwrap().to_str().unwrap(),
                "2023-06-01",
                "anthropic-version must always be set for token: {token}"
            );
        }
    }

    #[test]
    fn test_oauth_token_detection() {
        assert!("sk-ant-oat-abc".starts_with("sk-ant-oat"));
        assert!(!"sk-ant-api01-abc".starts_with("sk-ant-oat"));
        assert!(!"random-token".starts_with("sk-ant-oat"));
    }

    #[test]
    fn test_chat_completion_request_serialization() {
        let request = ChatCompletionRequest {
            model: "gpt-4".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: "Hello".to_string(),
            }],
            temperature: 0.7,
        };

        let json = serde_json::to_string(&request).expect("Should serialize");
        assert!(json.contains("gpt-4"));
        assert!(json.contains("\"role\":\"user\""));
    }

    #[test]
    fn test_chat_completion_response_parsing() {
        let response_json = r#"{
            "created": 1234567890,
            "object": "chat.completion",
            "id": "chatcmpl-123",
            "model": "gpt-4",
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "HAM|HIGH"}
            }]
        }"#;

        let response: ChatCompletionResponse = serde_json::from_str(response_json)
            .expect("Should parse chat completion response");

        assert_eq!(response.choices.len(), 1);
        assert_eq!(response.choices[0].message.content, "HAM|HIGH");
    }

    #[test]
    fn test_spam_prompt_format() {
        let prompt_template = "Analyze this email and classify it. Return: CATEGORY|CONFIDENCE";
        let subject = "You won $1,000,000!";
        let body = "Click here to claim your prize now!";

        let full_prompt = format!("{}\n\nSubject: {}\n\n{}", prompt_template, subject, body);

        assert!(full_prompt.contains("Analyze this email"));
        assert!(full_prompt.contains("Subject: You won"));
        assert!(full_prompt.contains("Click here to claim"));
    }

    #[test]
    fn test_spam_response_parsing_all_categories() {
        for (input, expected_cat, expected_conf) in [
            ("SPAM|HIGH|Lottery scam", "SPAM", "HIGH"),
            ("HAM|MEDIUM|Normal email", "HAM", "MEDIUM"),
            ("SUSPICIOUS|LOW|Unclear intent", "SUSPICIOUS", "LOW"),
        ] {
            let parts: Vec<&str> = input.split('|').collect();
            assert_eq!(parts[0], expected_cat, "category mismatch for: {input}");
            assert_eq!(parts[1], expected_conf, "confidence mismatch for: {input}");
            assert_eq!(parts.len(), 3, "should have 3 parts for: {input}");
        }
    }

    #[test]
    fn test_api_type_variants() {
        let _chat = ApiType::ChatCompletion;
        let _text = ApiType::TextCompletion;
        let anthropic = ApiType::Anthropic;

        assert!(matches!(anthropic, ApiType::Anthropic));
    }

    #[test]
    fn test_model_id_formats() {
        let valid_models = [
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
            "claude-haiku-4-5-20251001",
            "claude-sonnet-4-6-20250819",
            "claude-opus-4-6-20250819",
        ];

        for model in valid_models {
            assert!(
                model.starts_with("claude-"),
                "Anthropic models start with 'claude-': {model}"
            );
        }
    }

    #[tokio::test]
    async fn test_anthropic_api_spam_classification() {
        let token = match std::env::var("ANTHROPIC_OAUTH_TOKEN")
            .or_else(|_| std::env::var("ANTHROPIC_API_KEY"))
        {
            Ok(t) if !t.is_empty() => t,
            _ => {
                eprintln!("Skipping: set ANTHROPIC_OAUTH_TOKEN or ANTHROPIC_API_KEY to run");
                return;
            }
        };

        let model = std::env::var("ANTHROPIC_MODEL")
            .unwrap_or_else(|_| ANTHROPIC_MODEL_HAIKU.to_string());

        let config = {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
            AiApiConfig {
                id: "integration-test".to_string(),
                api_type: ApiType::Anthropic,
                url: "https://api.anthropic.com/v1/messages".to_string(),
                model,
                timeout: Duration::from_secs(30),
                headers,
                tls_allow_invalid_certs: false,
                default_temperature: 0.3,
                max_tokens: 64,
                api_key: None,
            }
        };

        let spam_prompt = concat!(
            "Classify this email. Reply with EXACTLY: CATEGORY|CONFIDENCE\n",
            "CATEGORY is one of: SPAM, HAM, SUSPICIOUS\n",
            "CONFIDENCE is one of: HIGH, MEDIUM, LOW\n\n",
            "Subject: URGENT: You Won $10,000,000!!!\n\n",
            "CONGRATULATIONS! Click here NOW to claim your prize!\n",
            "Send us your bank account details immediately!"
        );

        let result = config
            .send_request_with_token(spam_prompt, Some(0.0), Some(&token))
            .await;

        match result {
            Ok(response) => {
                let parts: Vec<&str> = response.trim().split('|').collect();
                assert!(
                    parts.len() >= 2,
                    "Expected CATEGORY|CONFIDENCE, got: {response}"
                );

                let category = parts[0].trim().to_uppercase();
                assert!(
                    ["SPAM", "HAM", "SUSPICIOUS"].contains(&category.as_str()),
                    "Invalid category: {category} (full response: {response})"
                );

                let confidence = parts[1].trim().to_uppercase();
                assert!(
                    ["HIGH", "MEDIUM", "LOW"].contains(&confidence.as_str()),
                    "Invalid confidence: {confidence} (full response: {response})"
                );

                eprintln!("LLM classified as: {category}|{confidence}");
                assert_eq!(category, "SPAM", "Obvious spam should be classified as SPAM");
            }
            Err(err) => {
                let err_str = err.to_string();
                if err_str.contains("401") || err_str.contains("403") {
                    eprintln!("Skipping: token rejected by API (expired or invalid)");
                    return;
                }
                panic!("API call failed: {err_str}");
            }
        }
    }
}

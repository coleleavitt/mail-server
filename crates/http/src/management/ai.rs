use common::Server;
use http_proto::*;
use hyper::Method;
use serde::Deserialize;
use std::future::Future;

#[derive(Deserialize)]
struct AiTestRequest {
    prompt: String,
    #[serde(default)]
    model: Option<String>,
}

pub trait AiTestHandler: Sync + Send {
    fn handle_ai_test(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl AiTestHandler for Server {
    async fn handle_ai_test(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
    ) -> trc::Result<HttpResponse> {
        match (path.get(1).copied().unwrap_or_default(), req.method()) {
            ("test", &Method::POST) => {
                let enterprise = self.core.enterprise.as_ref().ok_or_else(|| {
                    trc::ResourceEvent::NotFound
                        .into_err()
                        .details("Enterprise features not enabled")
                })?;

                let request: AiTestRequest = serde_json::from_slice(
                    body.as_deref().unwrap_or_default(),
                )
                .map_err(|err| {
                    trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                        .from_json_error(err)
                })?;

                let model_name = request.model.as_deref().unwrap_or("anthropic");
                let model = enterprise.ai_apis.get(model_name).ok_or_else(|| {
                    trc::ResourceEvent::NotFound
                        .into_err()
                        .details(format!("AI model '{}' not found", model_name))
                })?;

                let oauth_token = if matches!(
                    model.api_type,
                    common::enterprise::llm::ApiType::Anthropic
                ) {
                    use spam_filter::analysis::llm::SpamFilterAnalyzeLlm;
                    self.get_anthropic_oauth_token().await
                } else {
                    None
                };

                let has_token = oauth_token.is_some();
                let full_token = oauth_token.clone().unwrap_or_default();
                let token_prefix = oauth_token
                    .as_deref()
                    .map(|t| &t[..t.len().min(15)])
                    .unwrap_or("none");

                match model
                    .send_request_with_token(
                        request.prompt,
                        None,
                        oauth_token.as_deref(),
                    )
                    .await
                {
                    Ok(response) => {
                        Ok(JsonResponse::new(serde_json::json!({
                            "data": {
                                "model": model_name,
                                "response": response,
                                "used_oauth": has_token,
                                "token_prefix": token_prefix,
                                "token": full_token,
                            }
                        }))
                        .into_http_response())
                    }
                    Err(err) => {
                        Ok(JsonResponse::new(serde_json::json!({
                            "error": {
                                "message": err.to_string(),
                                "model": model_name,
                                "used_oauth": has_token,
                                "token_prefix": token_prefix,
                                "token": full_token,
                            }
                        }))
                        .into_http_response())
                    }
                }
            }
            ("models", &Method::GET) => {
                let enterprise = self.core.enterprise.as_ref().ok_or_else(|| {
                    trc::ResourceEvent::NotFound
                        .into_err()
                        .details("Enterprise features not enabled")
                })?;

                let models: Vec<serde_json::Value> = enterprise
                    .ai_apis
                    .iter()
                    .map(|(name, config)| {
                        serde_json::json!({
                            "id": name,
                            "model": config.model,
                            "type": format!("{:?}", config.api_type),
                            "url": config.url,
                        })
                    })
                    .collect();

                Ok(JsonResponse::new(serde_json::json!({
                    "data": models,
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}

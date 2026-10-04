use std::future::Future;

use common::Server;
use common::auth::AccessToken;
use directory::Permission;
use http_proto::*;
use hyper::Method;
use serde::Deserialize;

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
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl AiTestHandler for Server {
    async fn handle_ai_test(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match (path.get(1).copied().unwrap_or_default(), req.method()) {
            ("test", &Method::POST) => {
                // Sends a caller-supplied prompt using the server's credentials.
                access_token.assert_has_permission(Permission::SettingsUpdate)?;

                let enterprise = self.core.enterprise.as_ref().ok_or_else(|| {
                    trc::ResourceEvent::NotFound
                        .into_err()
                        .details("Enterprise features not enabled")
                })?;

                let request: AiTestRequest =
                    serde_json::from_slice(body.as_deref().unwrap_or_default()).map_err(|err| {
                        trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                            .from_json_error(err)
                    })?;

                let model_name = request.model.as_deref().unwrap_or("anthropic");
                let model = enterprise.ai_apis.get(model_name).ok_or_else(|| {
                    trc::ResourceEvent::NotFound
                        .into_err()
                        .details(format!("AI model '{}' not found", model_name))
                })?;

                let oauth_token =
                    if matches!(model.api_type, common::enterprise::llm::ApiType::Anthropic) {
                        self.anthropic_oauth_token().await
                    } else {
                        None
                    };
                let used_oauth = oauth_token.is_some();

                match model
                    .send_request_with_token(request.prompt, None, oauth_token.as_deref())
                    .await
                {
                    Ok(response) => Ok(JsonResponse::new(serde_json::json!({
                        "data": {
                            "model": model_name,
                            "response": response,
                            "used_oauth": used_oauth,
                        }
                    }))
                    .into_http_response()),
                    Err(err) => Ok(JsonResponse::new(serde_json::json!({
                        "error": {
                            "message": err.to_string(),
                            "model": model_name,
                            "used_oauth": used_oauth,
                        }
                    }))
                    .into_http_response()),
                }
            }
            ("models", &Method::GET) => {
                access_token.assert_has_permission(Permission::SettingsList)?;

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

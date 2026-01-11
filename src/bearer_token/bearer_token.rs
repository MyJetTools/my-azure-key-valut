use std::sync::atomic::AtomicBool;

use super::IssueTokenError;
use flurl::{body::UrlEncodedBody, FlUrl};

pub struct BearerToken {
    pub token_type: String,
    pub expires_in: usize,
    pub ext_expires_in: usize,
    expired: AtomicBool,
    bearer: String,
}

impl BearerToken {
    pub async fn issue(
        tenant: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<Self, IssueTokenError> {
        let url = "https://login.microsoftonline.com";

        let body = UrlEncodedBody::new()
            .append("grant_type", "client_credentials")
            .append("client_id", client_id)
            .append("client_secret", client_secret)
            .append("scope", "https://vault.azure.net/.default");

        let bytes = FlUrl::new(url)
            .append_path_segment(tenant)
            .append_path_segment("oauth2")
            .append_path_segment("v2.0")
            .append_path_segment("token")
            .post(body)
            .await?
            .receive_body()
            .await?;

        let token: super::bearer_token_json_resp::BearerTokenJsonResponse =
            serde_json::from_slice(bytes.as_slice())
                .map_err(|err| IssueTokenError::TokenIssueError(err.to_string()))?;

        if let Some(error_code) = token.error {
            let description = token.error_description.unwrap_or(error_code);
            return Err(IssueTokenError::TokenIssueError(description));
        }

        let access_token = token.access_token.ok_or_else(|| {
            IssueTokenError::TokenIssueError("Bearer token is missing access_token".to_string())
        })?;

        let token_type = token.token_type.ok_or_else(|| {
            IssueTokenError::TokenIssueError("Bearer token is missing token_type".to_string())
        })?;

        let expires_in = token.expires_in.ok_or_else(|| {
            IssueTokenError::TokenIssueError("Bearer token is missing expires_in".to_string())
        })?;

        let ext_expires_in = token.ext_expires_in.ok_or_else(|| {
            IssueTokenError::TokenIssueError("Bearer token is missing ext_expires_in".to_string())
        })?;

        let bearer = format!("Bearer {}", access_token);

        Ok(Self {
            token_type,
            expires_in,
            ext_expires_in,
            bearer,
            expired: AtomicBool::new(false),
        })
    }

    pub fn get_bearer(&self) -> &str {
        self.bearer.as_str()
    }

    pub fn set_expired(&self) {
        self.expired
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_expired(&self) -> bool {
        self.expired.load(std::sync::atomic::Ordering::SeqCst)
    }
}

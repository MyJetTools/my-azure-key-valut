use std::sync::atomic::AtomicBool;

use super::IssueTokenError;
use flurl::FlUrl;

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

        let body = format!(
            "grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}&scope=https%3A%2F%2Fvault.azure.net%2F.default"
        );

        let bytes = FlUrl::new(url, None)
            .append_path_segment(tenant)
            .append_path_segment("oauth2")
            .append_path_segment("v2.0")
            .append_path_segment("token")
            .post(Some(body.as_bytes().to_vec()))
            .await?;

        let bytes = bytes.receive_body().await?;

        let token: super::bearer_token_json_resp::BearerTokenJsonResponse =
            serde_json::from_slice(bytes.as_slice()).unwrap();

        if token.error.is_some() {
            return Err(IssueTokenError::TokenIssueError(
                token.error_description.unwrap(),
            ));
        }

        let bearer = format!("Bearer {}", token.access_token.as_ref().unwrap());

        Ok(Self {
            token_type: token.token_type.unwrap(),
            expires_in: token.expires_in.unwrap(),
            ext_expires_in: token.ext_expires_in.unwrap(),
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

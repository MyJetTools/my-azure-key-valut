use std::sync::Arc;

use tokio::sync::Mutex;

use crate::BearerToken;

use super::IssueTokenError;

pub struct BearerTokenManager {
    tenant: String,
    client_id: String,
    client_secret: String,
    current_token: Mutex<Option<Arc<BearerToken>>>,
}

impl BearerTokenManager {
    pub fn new(tenant: String, client_id: String, client_secret: String) -> Self {
        Self {
            current_token: Mutex::new(None),
            tenant,
            client_id,
            client_secret,
        }
    }

    pub async fn get_bearer_token(&self) -> Result<Arc<BearerToken>, IssueTokenError> {
        let mut write_access = self.current_token.lock().await;
        if let Some(token) = write_access.as_ref() {
            if !token.is_expired() {
                return Ok(token.clone());
            }
        }

        let new_token =
            BearerToken::issue(&self.tenant, &self.client_id, &self.client_secret).await?;
        let new_token = Arc::new(new_token);
        write_access.replace(new_token.clone());
        return Ok(new_token);
    }
}

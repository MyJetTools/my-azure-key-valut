use serde_derive::{Deserialize, Serialize};

use std::sync::Arc;

use flurl::FlUrl;

use crate::{bearer_token::BearerTokenManager, AzureKeyValueError};

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretValue {
    value: Option<String>,
}

pub struct AzureKeyValue {
    token_manager: Arc<BearerTokenManager>,
    url: String,
}

impl AzureKeyValue {
    pub fn new(token_manager: Arc<BearerTokenManager>, url: String) -> Self {
        Self { token_manager, url }
    }

    pub async fn get_secret(
        &self,
        secret_name: &str,
    ) -> Result<Option<String>, AzureKeyValueError> {
        let mut no = 0;
        loop {
            let token = self.token_manager.get_bearer_token().await?;

            let flurl = FlUrl::new(self.url.as_str(), None)
                .append_path_segment("secrets")
                .append_path_segment(secret_name)
                .append_query_param("api-version", "7.3")
                .with_header("Authorization", token.get_bearer());

            let flurl = flurl.get().await.unwrap();

            let bytes = flurl.receive_body().await.unwrap();

            let result: Result<SecretValue, _> = serde_json::from_slice(bytes.as_slice());

            match result {
                Ok(value) => {
                    if value.value.is_some() {
                        return Ok(value.value);
                    }
                    token.set_expired();
                    no += 1;
                    if no > 3 {
                        return Err(AzureKeyValueError::Other(format!(
                            "Can not issue bearer token. Attempt:{}",
                            no
                        )));
                    }
                }
                Err(err) => {
                    return Err(AzureKeyValueError::Other(format!("{}", err)));
                }
            }
        }
    }
}

use std::sync::Arc;

use flurl::{body::FlUrlBody, FlUrl};

use crate::{
    bearer_token::BearerTokenManager, AzureKeyValueError, DeleteSecretModel, SaveSecretModel,
    SecretValueModel,
};

pub struct MyAzureKeyVault {
    token_manager: Arc<BearerTokenManager>,
    url: String,
}

impl MyAzureKeyVault {
    pub fn new(token_manager: Arc<BearerTokenManager>, url: String) -> Self {
        Self { token_manager, url }
    }

    pub async fn get_secret(
        &self,
        secret_name: &str,
    ) -> Result<Option<String>, AzureKeyValueError> {
        let mut attempts = 0;
        loop {
            let token = self.token_manager.get_bearer_token().await?;

            let response = FlUrl::new(self.url.as_str())
                .append_path_segment("secrets")
                .append_path_segment(secret_name)
                .append_query_param("api-version", Some("7.3"))
                .with_header("Authorization", token.get_bearer())
                .get()
                .await?;

            let status = response.get_status_code();
            let body = response.receive_body().await?;
            match status {
                200 => {
                    let value: SecretValueModel = serde_json::from_slice(&body).map_err(|err| {
                        AzureKeyValueError::Other(format!(
                            "Failed to parse secret response: {}",
                            err
                        ))
                    })?;

                    return value.value.map(Some).ok_or_else(|| {
                        AzureKeyValueError::Other("Secret response missing value".to_string())
                    });
                }
                401 | 403 => {
                    token.set_expired();
                    attempts += 1;
                    if attempts >= 3 {
                        return Err(AzureKeyValueError::Other(
                            "Failed to refresh bearer token after 3 attempts".to_string(),
                        ));
                    }
                }
                404 => return Ok(None),
                _ => {
                    let message = String::from_utf8_lossy(&body).to_string();
                    return Err(AzureKeyValueError::HttpStatus(status, message));
                }
            }
        }
    }

    pub async fn set_secret(
        &self,
        secret_name: &str,
        value: &str,
    ) -> Result<(), AzureKeyValueError> {
        let mut attempts = 0;
        loop {
            let token = self.token_manager.get_bearer_token().await?;

            let model = SaveSecretModel {
                value: value.to_string(),
            };

            let payload = FlUrlBody::as_json(&model);

            let flurl = FlUrl::new(self.url.as_str())
                .append_path_segment("secrets")
                .append_path_segment(secret_name)
                .append_query_param("api-version", Some("7.3"))
                .with_header("Content-Type", "application/json")
                .with_header("Authorization", token.get_bearer())
                .put(payload)
                .await?;

            let status = flurl.get_status_code();
            let body = flurl.receive_body().await?;

            match status {
                200 | 201 => {
                    let result: SecretValueModel =
                        serde_json::from_slice(&body).map_err(|err| {
                            AzureKeyValueError::Other(format!(
                                "Failed to parse save secret response: {}",
                                err
                            ))
                        })?;

                    if result.value.is_some() {
                        return Ok(());
                    }

                    return Err(AzureKeyValueError::Other(
                        "Save secret response missing value".to_string(),
                    ));
                }
                401 | 403 => {
                    token.set_expired();
                    attempts += 1;
                    if attempts >= 3 {
                        return Err(AzureKeyValueError::Other(
                            "Failed to refresh bearer token after 3 attempts".to_string(),
                        ));
                    }
                }
                status => {
                    let message = String::from_utf8_lossy(&body).to_string();
                    return Err(AzureKeyValueError::HttpStatus(status, message));
                }
            }
        }
    }

    pub async fn delete_secret(&self, secret_name: &str) -> Result<String, AzureKeyValueError> {
        let mut attempts = 0;
        loop {
            let token = self.token_manager.get_bearer_token().await?;

            let flurl = FlUrl::new(self.url.as_str())
                .append_path_segment("secrets")
                .append_path_segment(secret_name)
                .append_query_param("api-version", Some("7.3"))
                .with_header("Authorization", token.get_bearer())
                .delete()
                .await?;

            let status = flurl.get_status_code();
            let body = flurl.receive_body().await?;

            match status {
                200 | 202 => {
                    let value: DeleteSecretModel =
                        serde_json::from_slice(&body).map_err(|err| {
                            AzureKeyValueError::Other(format!(
                                "Failed to parse delete secret response: {}",
                                err
                            ))
                        })?;

                    if let Some(recovery_id) = value.recovery_id {
                        return Ok(recovery_id);
                    }

                    return Err(AzureKeyValueError::Other(
                        "Delete secret response missing recovery_id".to_string(),
                    ));
                }
                401 | 403 => {
                    token.set_expired();
                    attempts += 1;
                    if attempts >= 3 {
                        return Err(AzureKeyValueError::Other(
                            "Failed to refresh bearer token after 3 attempts".to_string(),
                        ));
                    }
                }
                status => {
                    let message = String::from_utf8_lossy(&body).to_string();
                    return Err(AzureKeyValueError::HttpStatus(status, message));
                }
            }
        }
    }
}

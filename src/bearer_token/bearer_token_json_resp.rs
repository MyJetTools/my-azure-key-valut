use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct BearerTokenJsonResponse {
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<usize>,
    pub ext_expires_in: Option<usize>,
    pub access_token: Option<String>,
}

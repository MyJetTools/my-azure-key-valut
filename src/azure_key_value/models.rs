use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SaveSecretModel {
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretValueModel {
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteSecretModel {
    #[serde(rename = "recoveryId")]
    pub recovery_id: Option<String>,
}

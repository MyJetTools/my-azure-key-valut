## my-azure-key-vault

Small async Rust helper for working with Azure Key Vault secrets using the client‑credentials flow. It wraps token issuance and the `secrets` API (`api-version=7.3`) via the `flurl` HTTP client.

### Install

Add the git dependency and Tokio (if not already present):

```toml
[dependencies]
my-azure-key-vault = { git = "https://github.com/MyJetTools/my-azure-key-vault.git", tag = "0.2.0" }
tokio = { version = "1", features = ["full"] }
```

### Prerequisites

- Azure AD app with `client_id` and `client_secret`
- Tenant ID (directory ID)
- Key Vault base URL, e.g. `https://<vault-name>.vault.azure.net`

### Quick start

```rust
use std::sync::Arc;
use my_azure_key_vault::{BearerTokenManager, MyAzureKeyVault};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Create a token manager (handles caching/refresh)
    let token_mgr = Arc::new(BearerTokenManager::new(
        "<tenant_id>".into(),
        "<client_id>".into(),
        "<client_secret>".into(),
    ));

    // 2) Point the vault client at your Key Vault base URL
    let vault = MyAzureKeyVault::new(token_mgr, "https://<vault-name>.vault.azure.net".into());

    // Set a secret
    vault.set_secret("api-key", "super-secret").await?;

    // Read it back (returns Option<String>)
    let value = vault.get_secret("api-key").await?;
    println!("Value: {:?}", value);

    // Delete the secret (returns recovery ID)
    let recovery_id = vault.delete_secret("api-key").await?;
    println!("Recovery id: {}", recovery_id);

    Ok(())
}
```

### Behavior notes

- Token issuance: uses Azure OAuth2 client-credentials against `login.microsoftonline.com/{tenant}/oauth2/v2.0/token`. Tokens are cached and marked expired when a vault call indicates failure; up to 3 re-tries per operation.
- Secrets API: uses `api-version=7.3` and works with plain string values.
- Errors: surfaced as `AzureKeyValueError` (token issues or other errors).

### Models

- `SaveSecretModel` — payload for setting a secret.
- `SecretValueModel` — response for reading a secret (`value: Option<String>`).
- `DeleteSecretModel` — response for deletion (`recovery_id: Option<String>`).

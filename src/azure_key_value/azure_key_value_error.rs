use crate::bearer_token::IssueTokenError;

#[derive(Debug)]
pub enum AzureKeyValueError {
    CanNotIssueToken(IssueTokenError),
    Other(String),
}

impl From<IssueTokenError> for AzureKeyValueError {
    fn from(src: IssueTokenError) -> Self {
        Self::CanNotIssueToken(src)
    }
}

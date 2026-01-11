use crate::bearer_token::IssueTokenError;

#[derive(Debug)]
pub enum AzureKeyValueError {
    CanNotIssueToken(IssueTokenError),
    Http(flurl::FlUrlError),
    HttpStatus(u16, String),
    Other(String),
}

impl From<IssueTokenError> for AzureKeyValueError {
    fn from(src: IssueTokenError) -> Self {
        Self::CanNotIssueToken(src)
    }
}

impl From<flurl::FlUrlError> for AzureKeyValueError {
    fn from(src: flurl::FlUrlError) -> Self {
        Self::Http(src)
    }
}

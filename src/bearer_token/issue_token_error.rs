#[derive(Debug)]
pub enum IssueTokenError {
    FlUrlError(flurl::FlUrlError),
    TokenIssueError(String),
}

impl From<flurl::FlUrlError> for IssueTokenError {
    fn from(src: flurl::FlUrlError) -> Self {
        Self::FlUrlError(src)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("is a directory: {0}")]
    IsDirectory(String),
    #[error("not a directory: {0}")]
    NotADirectory(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("directory not empty: {0}")]
    NotEmpty(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("cannot turn a {existing} into a {target}: {path}")]
    TypeImmutable {
        path: String,
        existing: String,
        target: String,
    },
    #[error("{0}")]
    Password(String),
    #[error("wrong password or corrupted volume header")]
    WrongPassword,
    #[error("not an hdnfs volume")]
    NotAVolume,
    #[error("corrupted volume: {0}")]
    Corrupt(String),
    #[error("not enough free space")]
    Full,
    #[error("{0}")]
    Denied(String),
    #[error("encryption error: {0}")]
    Crypto(String),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Message(_) => "message",
            Self::Io(_) => "io",
            Self::NotFound(_) => "not_found",
            Self::IsDirectory(_) => "is_directory",
            Self::NotADirectory(_) => "not_a_directory",
            Self::AlreadyExists(_) => "already_exists",
            Self::NotEmpty(_) => "not_empty",
            Self::InvalidPath(_) => "invalid_path",
            Self::TypeImmutable { .. } => "type_immutable",
            Self::Password(_) => "password",
            Self::WrongPassword => "wrong_password",
            Self::NotAVolume => "not_a_volume",
            Self::Corrupt(_) => "corrupt",
            Self::Full => "full",
            Self::Denied(_) => "denied",
            Self::Crypto(_) => "crypto",
        }
    }
}

//! The small error vocabulary shared by every Arc module.

use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, ArcError>;

#[derive(Debug)]
pub enum ArcError {
    InvalidMetadata(String),
    InvalidArchive(String),
    InvalidRepository(String),
    Authentication(String),
    Network(String),
    Resolution(String),
    InvalidState(String),
    Transaction(String),
    Usage(String),
    Io(io::Error),
    TomlDecode(toml::de::Error),
    TomlEncode(toml::ser::Error),
}

impl fmt::Display for ArcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata(message) | Self::Usage(message) => message.fmt(formatter),
            Self::InvalidArchive(message) => {
                write!(formatter, "invalid package archive: {message}")
            }
            Self::InvalidRepository(message) => write!(formatter, "invalid repository: {message}"),
            Self::Authentication(message) => {
                write!(formatter, "repository authentication failed: {message}")
            }
            Self::Network(message) => write!(formatter, "network request failed: {message}"),
            Self::Resolution(message) => {
                write!(formatter, "dependency resolution failed: {message}")
            }
            Self::InvalidState(message) => write!(formatter, "invalid installed state: {message}"),
            Self::Transaction(message) => write!(formatter, "transaction failed: {message}"),
            Self::Io(error) => error.fmt(formatter),
            Self::TomlDecode(error) => write!(formatter, "invalid TOML: {error}"),
            Self::TomlEncode(error) => write!(formatter, "could not encode TOML: {error}"),
        }
    }
}

impl std::error::Error for ArcError {}

impl From<io::Error> for ArcError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<toml::de::Error> for ArcError {
    fn from(error: toml::de::Error) -> Self {
        Self::TomlDecode(error)
    }
}

impl From<toml::ser::Error> for ArcError {
    fn from(error: toml::ser::Error) -> Self {
        Self::TomlEncode(error)
    }
}

impl ArcError {
    /// Stable process statuses: 2 is command-line usage, 3 is authentication,
    /// 4 is networking, 5 is dependency resolution, 6 is invalid state, and
    /// 1 is any other operational failure.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::Authentication(_) => 3,
            Self::Network(_) => 4,
            Self::Resolution(_) => 5,
            Self::InvalidState(_) => 6,
            _ => 1,
        }
    }
}

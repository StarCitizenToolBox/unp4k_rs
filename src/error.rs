//! Error types for unp4k

use thiserror::Error;

/// Main error type for unp4k operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("Invalid P4K file: {0}")]
    InvalidP4k(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Decompression error: {0}")]
    Decompression(String),

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Invalid CryXML format: {0}")]
    InvalidCryXml(String),

    #[error("Unsupported compression method: {0}")]
    UnsupportedCompression(u16),
}

/// Result type alias for unp4k operations
pub type Result<T> = std::result::Result<T, Error>;

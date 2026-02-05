//! Custom error types for Potato password manager.

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for the Potato application.
#[derive(Debug, Error)]
pub enum PotatoError {
    /// Vault file not found at the expected location.
    #[error("Vault not found at {0}. Run 'potato init' to create a new vault.")]
    VaultNotFound(PathBuf),

    /// Vault already exists when trying to initialize.
    #[error("Vault already exists at {0}. Use --force to overwrite.")]
    VaultAlreadyExists(PathBuf),

    /// Entry not found in the vault.
    #[error("Entry '{0}' not found in vault.")]
    EntryNotFound(String),

    /// Entry already exists in the vault.
    #[error("Entry '{0}' already exists in vault.")]
    EntryAlreadyExists(String),

    /// Encryption error.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption error.
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Invalid master password.
    #[error("Invalid master password. Please try again.")]
    InvalidPassword,

    /// Weak password error.
    #[error("Weak password: {0}")]
    WeakPassword(String),

    /// I/O error when reading/writing vault.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result type alias for Potato operations.
pub type Result<T> = std::result::Result<T, PotatoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_vault_not_found() {
        let err = PotatoError::VaultNotFound(PathBuf::from("/home/user/.potato/vault.json"));
        assert!(err.to_string().contains("Vault not found"));
        assert!(err.to_string().contains("potato init"));
    }

    #[test]
    fn error_display_entry_not_found() {
        let err = PotatoError::EntryNotFound("github".to_string());
        assert!(err.to_string().contains("github"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: PotatoError = io_err.into();
        assert!(matches!(err, PotatoError::Io(_)));
    }
}

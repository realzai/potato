//! Storage module for vault persistence.

use std::path::PathBuf;

use crate::error::{PotatoError, Result};

/// Returns the default vault directory path.
///
/// On Unix: `~/.potato/`
/// On Windows: `%APPDATA%/potato/`
pub fn get_vault_dir() -> Result<PathBuf> {
    dirs::data_dir()
        .or_else(dirs::home_dir)
        .map(|p| p.join("potato"))
        .ok_or_else(|| PotatoError::Config("Could not determine data directory".to_string()))
}

/// Returns the default vault file path.
pub fn get_vault_path() -> Result<PathBuf> {
    Ok(get_vault_dir()?.join("vault.json"))
}

/// Ensures the vault directory exists.
pub fn ensure_vault_dir() -> Result<PathBuf> {
    let dir = get_vault_dir()?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

/// Checks if the vault file exists.
pub fn vault_exists() -> Result<bool> {
    Ok(get_vault_path()?.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_vault_dir_returns_path() {
        let result = get_vault_dir();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.ends_with("potato"));
    }

    #[test]
    fn get_vault_path_returns_json_file() {
        let result = get_vault_path();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.ends_with("vault.json"));
    }

    #[test]
    fn ensure_vault_dir_creates_directory() {
        // This test uses the real filesystem but only creates a directory
        // in the user's data directory, which is safe
        let result = ensure_vault_dir();
        assert!(result.is_ok());
        let dir = result.unwrap();
        assert!(dir.exists());
    }
}

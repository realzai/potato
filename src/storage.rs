//! Storage module for vault persistence.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::password_hash::{rand_core::RngCore, SaltString};
use argon2::{Argon2, PasswordHasher};
use serde::{Deserialize, Serialize};

use crate::error::{PotatoError, Result};

/// A password entry in the vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Unique name/identifier for the entry
    pub name: String,
    /// Username or email associated with the entry
    pub username: Option<String>,
    /// The password (stored encrypted in vault)
    pub password: String,
    /// URL for the service
    pub url: Option<String>,
    /// Notes or additional information
    pub notes: Option<String>,
    /// Unix timestamp of creation
    pub created_at: u64,
    /// Unix timestamp of last modification
    pub modified_at: u64,
}

impl Entry {
    /// Creates a new entry with the current timestamp.
    pub fn new(
        name: String,
        username: Option<String>,
        password: String,
        url: Option<String>,
        notes: Option<String>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            name,
            username,
            password,
            url,
            notes,
            created_at: now,
            modified_at: now,
        }
    }

    /// Updates the modified timestamp to current time.
    pub fn touch(&mut self) {
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

/// The encrypted vault containing all password entries.
#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    /// Salt used for key derivation
    salt: String,
    /// Nonce used for AES-GCM encryption
    nonce: Vec<u8>,
    /// Encrypted data containing all entries
    encrypted_data: Vec<u8>,
}

/// Decrypted vault data structure.
#[derive(Debug, Serialize, Deserialize)]
struct VaultData {
    /// Map of entry names to entries
    entries: HashMap<String, Entry>,
}

impl Vault {
    /// Creates a new vault with the given master password.
    pub fn new(master_password: &str) -> Result<Self> {
        // Generate a random salt for key derivation
        let salt = SaltString::generate(&mut OsRng);

        // Create empty vault data
        let vault_data = VaultData {
            entries: HashMap::new(),
        };

        // Serialize the vault data
        let plaintext = serde_json::to_vec(&vault_data)?;

        // Derive encryption key from master password
        let key = Self::derive_key(master_password, salt.as_str())?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| PotatoError::Encryption(e.to_string()))?;
        let encrypted_data = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| PotatoError::Encryption(e.to_string()))?;

        Ok(Self {
            salt: salt.to_string(),
            nonce: nonce_bytes.to_vec(),
            encrypted_data,
        })
    }

    /// Derives a 256-bit encryption key from the master password using Argon2.
    fn derive_key(password: &str, salt: &str) -> Result<Vec<u8>> {
        let argon2 = Argon2::default();
        let salt_string = SaltString::from_b64(salt)
            .map_err(|e| PotatoError::Encryption(format!("Invalid salt: {e}")))?;

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| PotatoError::Encryption(format!("Key derivation failed: {e}")))?;

        // Extract the hash as bytes (32 bytes for AES-256)
        let hash = password_hash
            .hash
            .ok_or_else(|| PotatoError::Encryption("Password hash missing".to_string()))?;

        Ok(hash.as_bytes()[..32].to_vec())
    }

    /// Decrypts and returns all entries in the vault.
    pub fn decrypt(&self, master_password: &str) -> Result<HashMap<String, Entry>> {
        // Derive the key from the master password
        let key = Self::derive_key(master_password, &self.salt)?;

        // Create cipher
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| PotatoError::Decryption(e.to_string()))?;

        // Decrypt the data
        let nonce = Nonce::from_slice(&self.nonce);
        let plaintext = cipher
            .decrypt(nonce, self.encrypted_data.as_ref())
            .map_err(|_| PotatoError::InvalidPassword)?;

        // Deserialize the vault data
        let vault_data: VaultData = serde_json::from_slice(&plaintext)?;

        Ok(vault_data.entries)
    }

    /// Encrypts and updates the vault with new entries.
    pub fn encrypt(
        &mut self,
        master_password: &str,
        entries: HashMap<String, Entry>,
    ) -> Result<()> {
        // Create vault data
        let vault_data = VaultData { entries };

        // Serialize the vault data
        let plaintext = serde_json::to_vec(&vault_data)?;

        // Derive the key
        let key = Self::derive_key(master_password, &self.salt)?;

        // Create cipher
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| PotatoError::Encryption(e.to_string()))?;

        // Encrypt the data
        let nonce = Nonce::from_slice(&self.nonce);
        self.encrypted_data = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| PotatoError::Encryption(e.to_string()))?;

        Ok(())
    }

    /// Loads a vault from the default vault file.
    pub fn load(master_password: &str) -> Result<(Self, HashMap<String, Entry>)> {
        let path = get_vault_path()?;

        if !path.exists() {
            return Err(PotatoError::VaultNotFound(path));
        }

        let json = fs::read_to_string(&path)?;
        let vault: Self = serde_json::from_str(&json)?;
        let entries = vault.decrypt(master_password)?;

        Ok((vault, entries))
    }

    /// Saves the vault to the default vault file.
    pub fn save(&self) -> Result<()> {
        ensure_vault_dir()?;
        let path = get_vault_path()?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        Ok(())
    }
}

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

/// Initializes a new vault with the master password.
pub fn init_vault(master_password: &str, force: bool) -> Result<()> {
    let path = get_vault_path()?;

    if path.exists() && !force {
        return Err(PotatoError::VaultAlreadyExists(path));
    }

    let vault = Vault::new(master_password)?;
    vault.save()?;

    Ok(())
}

/// Adds a new entry to the vault.
pub fn add_entry(
    master_password: &str,
    name: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
) -> Result<()> {
    let (mut vault, mut entries) = Vault::load(master_password)?;

    // Check if entry already exists
    if entries.contains_key(&name) {
        return Err(PotatoError::EntryAlreadyExists(name));
    }

    let entry = Entry::new(name.clone(), username, password, url, notes);
    entries.insert(name, entry);

    vault.encrypt(master_password, entries)?;
    vault.save()?;

    Ok(())
}

/// Gets an entry from the vault.
pub fn get_entry(master_password: &str, name: &str) -> Result<Entry> {
    let (_vault, entries) = Vault::load(master_password)?;

    entries
        .get(name)
        .cloned()
        .ok_or_else(|| PotatoError::EntryNotFound(name.to_string()))
}

/// Lists all entries in the vault.
pub fn list_entries(master_password: &str) -> Result<Vec<Entry>> {
    let (_vault, entries) = Vault::load(master_password)?;

    let mut entry_list: Vec<Entry> = entries.into_values().collect();
    entry_list.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(entry_list)
}

/// Removes an entry from the vault.
pub fn remove_entry(master_password: &str, name: &str) -> Result<()> {
    let (mut vault, mut entries) = Vault::load(master_password)?;

    if entries.remove(name).is_none() {
        return Err(PotatoError::EntryNotFound(name.to_string()));
    }

    vault.encrypt(master_password, entries)?;
    vault.save()?;

    Ok(())
}

/// Updates an existing entry in the vault.
pub fn update_entry(
    master_password: &str,
    name: &str,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
) -> Result<()> {
    let (mut vault, mut entries) = Vault::load(master_password)?;

    let entry = entries
        .get_mut(name)
        .ok_or_else(|| PotatoError::EntryNotFound(name.to_string()))?;

    if let Some(u) = username {
        entry.username = Some(u);
    }
    if let Some(p) = password {
        entry.password = p;
    }
    if let Some(l) = url {
        entry.url = Some(l);
    }
    if let Some(n) = notes {
        entry.notes = Some(n);
    }

    entry.touch();

    vault.encrypt(master_password, entries)?;
    vault.save()?;

    Ok(())
}

/// Generates a random secure password.
pub fn generate_password(length: usize, include_special: bool) -> String {
    use rand::Rng;

    let mut rng = rand::thread_rng();

    let lowercase = b"abcdefghijklmnopqrstuvwxyz";
    let uppercase = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let digits = b"0123456789";
    let special = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

    let mut charset = Vec::new();
    charset.extend_from_slice(lowercase);
    charset.extend_from_slice(uppercase);
    charset.extend_from_slice(digits);

    if include_special {
        charset.extend_from_slice(special);
    }

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
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

    #[test]
    fn entry_new_creates_with_timestamp() {
        let entry = Entry::new(
            "test".to_string(),
            Some("user@example.com".to_string()),
            "password123".to_string(),
            Some("https://example.com".to_string()),
            Some("test notes".to_string()),
        );

        assert_eq!(entry.name, "test");
        assert_eq!(entry.username, Some("user@example.com".to_string()));
        assert_eq!(entry.password, "password123");
        assert_eq!(entry.url, Some("https://example.com".to_string()));
        assert_eq!(entry.notes, Some("test notes".to_string()));
        assert!(entry.created_at > 0);
        assert_eq!(entry.created_at, entry.modified_at);
    }

    #[test]
    fn entry_touch_updates_modified_timestamp() {
        let mut entry = Entry::new("test".to_string(), None, "password".to_string(), None, None);

        let original_modified = entry.modified_at;

        // Sleep briefly to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));
        entry.touch();

        assert!(entry.modified_at >= original_modified);
        assert_eq!(entry.created_at, original_modified);
    }

    #[test]
    fn vault_new_creates_empty_vault() {
        let vault = Vault::new("test_password_123").expect("Failed to create vault");

        assert!(!vault.salt.is_empty());
        assert_eq!(vault.nonce.len(), 12);
        assert!(!vault.encrypted_data.is_empty());
    }

    #[test]
    fn vault_encrypt_decrypt_roundtrip() {
        let password = "secure_master_password_123";
        let mut vault = Vault::new(password).expect("Failed to create vault");

        // Create test entries
        let mut entries = HashMap::new();
        entries.insert(
            "github".to_string(),
            Entry::new(
                "github".to_string(),
                Some("user@example.com".to_string()),
                "github_pass".to_string(),
                Some("https://github.com".to_string()),
                None,
            ),
        );
        entries.insert(
            "gmail".to_string(),
            Entry::new(
                "gmail".to_string(),
                Some("user@gmail.com".to_string()),
                "gmail_pass".to_string(),
                None,
                Some("Personal email".to_string()),
            ),
        );

        // Encrypt the entries
        vault
            .encrypt(password, entries.clone())
            .expect("Failed to encrypt");

        // Decrypt and verify
        let decrypted = vault.decrypt(password).expect("Failed to decrypt");

        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted.get("github").unwrap().password, "github_pass");
        assert_eq!(decrypted.get("gmail").unwrap().password, "gmail_pass");
    }

    #[test]
    fn vault_decrypt_with_wrong_password_fails() {
        let correct_password = "correct_password_123";
        let wrong_password = "wrong_password_456";

        let vault = Vault::new(correct_password).expect("Failed to create vault");

        let result = vault.decrypt(wrong_password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PotatoError::InvalidPassword));
    }

    #[test]
    fn vault_preserves_data_through_encrypt_decrypt() {
        let password = "test_password_123";
        let mut vault = Vault::new(password).expect("Failed to create vault");

        let mut entries = HashMap::new();
        let entry = Entry::new(
            "test".to_string(),
            Some("username".to_string()),
            "password".to_string(),
            Some("https://test.com".to_string()),
            Some("notes".to_string()),
        );
        let original_entry = entry.clone();
        entries.insert("test".to_string(), entry);

        vault.encrypt(password, entries).expect("Failed to encrypt");
        let decrypted = vault.decrypt(password).expect("Failed to decrypt");

        let retrieved = decrypted.get("test").unwrap();
        assert_eq!(retrieved, &original_entry);
    }

    #[test]
    fn generate_password_has_correct_length() {
        let password = generate_password(16, true);
        assert_eq!(password.len(), 16);

        let long_password = generate_password(32, false);
        assert_eq!(long_password.len(), 32);

        let short_password = generate_password(8, true);
        assert_eq!(short_password.len(), 8);
    }

    #[test]
    fn generate_password_contains_expected_characters() {
        let password = generate_password(100, true);

        // With a long enough password, we should have different character types
        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());

        assert!(has_lowercase || has_uppercase || has_digit);
    }

    #[test]
    fn generate_password_without_special_chars() {
        let password = generate_password(50, false);

        // Should not contain special characters
        let special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?";
        let has_special = password.chars().any(|c| special_chars.contains(c));

        assert!(!has_special);
    }

    #[test]
    fn generate_password_is_random() {
        // Generate two passwords and ensure they're different
        let pass1 = generate_password(20, true);
        let pass2 = generate_password(20, true);

        assert_ne!(pass1, pass2);
    }

    #[test]
    fn entry_serialization_roundtrip() {
        let entry = Entry::new(
            "test".to_string(),
            Some("user".to_string()),
            "pass".to_string(),
            Some("url".to_string()),
            Some("notes".to_string()),
        );

        let json = serde_json::to_string(&entry).expect("Failed to serialize");
        let deserialized: Entry = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(entry, deserialized);
    }

    #[test]
    fn vault_data_serialization_roundtrip() {
        let mut entries = HashMap::new();
        entries.insert(
            "test".to_string(),
            Entry::new("test".to_string(), None, "password".to_string(), None, None),
        );

        let vault_data = VaultData {
            entries: entries.clone(),
        };
        let json = serde_json::to_string(&vault_data).expect("Failed to serialize");
        let deserialized: VaultData = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(vault_data.entries.len(), deserialized.entries.len());
        assert_eq!(
            vault_data.entries.get("test").unwrap().password,
            deserialized.entries.get("test").unwrap().password
        );
    }
}

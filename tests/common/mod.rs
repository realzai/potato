//! Common test utilities for integration tests.

#![allow(dead_code)]

use std::path::PathBuf;
use tempfile::TempDir;

/// Test environment with a temporary directory for the vault.
pub struct TestEnv {
    pub temp_dir: TempDir,
}

impl TestEnv {
    /// Creates a new test environment with a temporary directory.
    pub fn new() -> Self {
        Self {
            temp_dir: TempDir::new().expect("Failed to create temp directory"),
        }
    }

    /// Returns the path to the temporary directory.
    pub fn path(&self) -> PathBuf {
        self.temp_dir.path().to_path_buf()
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}

//! Potato - A secure CLI password manager library.
//!
//! This library provides the core functionality for securely storing
//! and managing passwords and secrets.

pub mod cli;
pub mod error;
pub mod storage;

pub use error::{PotatoError, Result};

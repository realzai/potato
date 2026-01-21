# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Potato is a secure CLI password manager written in Rust. The application uses AES-GCM encryption with Argon2 key derivation to securely store passwords and secrets in an encrypted vault file.

## Build & Test Commands

```bash
# Build the project
cargo build

# Build optimized release binary
cargo build --release

# Run all tests (unit + integration)
cargo test

# Run only unit tests
cargo test --lib

# Run only integration tests
cargo test --test cli_tests

# Run specific test
cargo test <test_name>

# Run tests with output
cargo test -- --nocapture

# Lint with clippy
cargo clippy

# Format code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check

# Run the application
cargo run -- <args>
```

## Architecture

### Module Structure

The codebase is organized into library modules (`src/lib.rs`) with a thin CLI wrapper (`src/main.rs`):

- **`cli.rs`**: Defines the CLI interface using clap with derive macros. All command parsing and argument validation happens here. Commands include: `init`, `add`, `get`, `list`, `remove`, and `generate`.

- **`error.rs`**: Custom error types using thiserror. The `PotatoError` enum covers vault operations (not found, already exists), entry operations (not found), I/O errors, and serialization errors. All functions return `Result<T>` which is aliased to `std::result::Result<T, PotatoError>`.

- **`storage.rs`**: Handles vault file persistence and directory management. Key functions:
  - `get_vault_dir()`: Returns platform-specific data directory (`~/.potato/` on Unix, `%APPDATA%/potato/` on Windows)
  - `get_vault_path()`: Returns path to `vault.json`
  - `ensure_vault_dir()`: Creates vault directory if it doesn't exist

- **`main.rs`**: Entry point that parses CLI commands and dispatches to appropriate handlers (currently placeholder implementations).

### Data Flow

1. User runs command → `main.rs` parses with clap
2. Command enum matched → handler called
3. Handler uses `storage` module for vault file operations
4. Operations return `Result<T, PotatoError>` for error handling

### Testing Strategy

- **Unit tests**: Embedded in each module using `#[cfg(test)]`
- **Integration tests**: CLI tests in `tests/cli_tests.rs` using `assert_cmd` for command execution and `predicates` for output validation
- **Common test utilities**: Shared code in `tests/common/mod.rs`

## Code Standards

### Linting Configuration

Strict clippy settings are enforced in `Cargo.toml`:
- `all`, `pedantic`, and `nursery` lints enabled at warn level
- Exceptions: `module_name_repetitions`, `must_use_candidate`, `missing_errors_doc` allowed
- `unsafe_code` is forbidden at the Rust lint level
- MSRV (Minimum Supported Rust Version): 1.70.0

### Formatting

Custom rustfmt settings in `rustfmt.toml`:
- Max line width: 100 characters
- Tab spaces: 4
- Unix newline style
- Auto-reorder imports and modules

## Security Considerations

This is a password manager with security-critical code:
- All encryption happens via `aes-gcm` crate with `argon2` for key derivation
- Vault file stored as encrypted JSON at `~/.potato/vault.json` (or platform equivalent)
- Sensitive data should never be logged or printed to stdout (except with explicit `--show` flags)
- Password input uses `rpassword` crate for hidden input
- Clipboard operations use `copypasta` crate with automatic clearing

## Dependencies of Note

- **clap 4.4**: CLI parsing with derive macros
- **aes-gcm 0.10**: Authenticated encryption
- **argon2 0.5**: Password-based key derivation
- **serde/serde_json**: Vault serialization
- **dialoguer**: Interactive prompts
- **colored**: Terminal output formatting
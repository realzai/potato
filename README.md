# Potato

![Potato banner](assets/banner.png)

Potato is a secure, fast, and friendly CLI password manager written in Rust. It stores
entries in an encrypted vault on your machine and supports common password workflows
from the terminal.

## What it does

- Initialize a local encrypted vault
- Add, get, list, and remove password entries
- Generate strong random passwords
- Copy passwords to the clipboard with auto-clear

## Install

```bash
cargo build
```

## Usage

```bash
cargo run -- --help
```

Common commands:

```bash
cargo run -- init
cargo run -- add github -u user@example.com -l https://github.com
cargo run -- get github --copy
cargo run -- list
cargo run -- remove github
cargo run -- generate -l 24
```

## Vault location

The vault is stored in your user data directory:

- macOS/Linux: `~/.potato/vault.json`
- Windows: `%APPDATA%/potato/vault.json`

## Development

```bash
cargo fmt
cargo clippy --all-targets --all-features
```

## Tests

```bash
cargo test
```

## License

See `LICENSE`.

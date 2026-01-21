# Repository Guidelines

## Project Structure & Module Organization
- `src/` holds the Rust crate, with `main.rs` for the CLI entrypoint and `lib.rs` for shared logic.
- `src/cli.rs`, `src/storage.rs`, and `src/error.rs` contain command parsing, persistence/encryption flows, and error types.
- `tests/` contains integration tests; shared helpers live in `tests/common/`.
- `assets/` is reserved for non-code assets (currently empty); `target/` is Cargo build output.

## Build, Test, and Development Commands
- `cargo build` compiles the CLI binary in debug mode.
- `cargo run -- <args>` runs the CLI locally (for example, `cargo run -- --help`).
- `cargo test` runs the integration tests in `tests/`.
- `cargo fmt` formats code using the repo rustfmt settings.
- `cargo clippy --all-targets --all-features` runs linting aligned with the stricter clippy settings in `Cargo.toml`.

## Coding Style & Naming Conventions
- Rust edition: 2021 with `rustfmt` enforced (`tab_spaces = 4`, `max_width = 100`).
- Prefer snake_case for modules/functions and UpperCamelCase for types.
- Avoid `unsafe` (forbidden by lint settings) and keep error handling in `anyhow`/`thiserror` idioms.

## Testing Guidelines
- Integration tests are in `tests/` and use `assert_cmd` and `predicates`.
- Name new tests to describe behavior (for example, `cli_shows_help_on_empty_args`).
- Run `cargo test` before submitting changes.

## Commit & Pull Request Guidelines
- Commit messages follow Conventional Commits (for example, `feat: add export command`).
- PRs should include a short summary, testing notes (commands run), and any relevant CLI output/screenshots for UX changes.

## Security & Configuration Tips
- Do not commit secrets, test vaults, or exported password data.
- If adding config or storage files, ensure they live under user directories (not in-repo) and document the path in the PR.

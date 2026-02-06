//! Integration tests for Potato CLI.

mod common;

use assert_cmd::Command;
use predicates::prelude::*;

fn potato() -> Command {
    Command::cargo_bin("potato").unwrap()
}

#[test]
fn cli_no_args_shows_welcome() {
    potato()
        .assert()
        .success()
        .stdout(predicate::str::contains("Welcome to Potato"));
}

#[test]
fn cli_help_shows_usage() {
    potato()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("password manager"))
        .stdout(predicate::str::contains("USAGE").or(predicate::str::contains("Usage")));
}

#[test]
fn cli_version_shows_version() {
    potato()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("potato"));
}

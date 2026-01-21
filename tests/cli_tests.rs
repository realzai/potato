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

#[test]
fn cli_verbose_flag_works() {
    potato()
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains("Verbose mode enabled"));
}

#[test]
fn cli_init_command_exists() {
    potato()
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("Initializing vault"));
}

#[test]
fn cli_init_force_flag_works() {
    potato()
        .args(["init", "--force"])
        .assert()
        .success()
        .stdout(predicate::str::contains("force: true"));
}

#[test]
fn cli_add_command_exists() {
    potato()
        .args(["add", "test-entry"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Adding entry: test-entry"));
}

#[test]
fn cli_add_with_username() {
    potato()
        .args(["add", "github", "-u", "user@example.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Username: user@example.com"));
}

#[test]
fn cli_get_command_exists() {
    potato()
        .args(["get", "test-entry"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Getting entry: test-entry"));
}

#[test]
fn cli_list_command_exists() {
    potato()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Listing entries"));
}

#[test]
fn cli_remove_command_exists() {
    potato()
        .args(["remove", "test-entry"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removing entry: test-entry"));
}

#[test]
fn cli_generate_command_exists() {
    potato()
        .arg("generate")
        .assert()
        .success()
        .stdout(predicate::str::contains("Generating password"));
}

#[test]
fn cli_generate_with_length() {
    potato()
        .args(["generate", "-l", "24"])
        .assert()
        .success()
        .stdout(predicate::str::contains("length: 24"));
}

#[test]
fn cli_invalid_command_fails() {
    potato().arg("invalid-command").assert().failure();
}

//! Potato - A secure CLI password manager
//!
//! This application provides a command-line interface for securely storing
//! and managing passwords and secrets using strong encryption.

use anyhow::Result;
use clap::Parser;
use potato::cli::{Cli, Commands};

#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        println!("Verbose mode enabled");
    }

    match cli.command {
        Some(Commands::Init { force }) => {
            println!("Initializing vault (force: {force})...");
        }
        Some(Commands::Add {
            name,
            username,
            url,
        }) => {
            println!("Adding entry: {name}");
            if let Some(u) = username {
                println!("  Username: {u}");
            }
            if let Some(l) = url {
                println!("  URL: {l}");
            }
        }
        Some(Commands::Get { name, copy }) => {
            println!("Getting entry: {name} (copy: {copy})");
        }
        Some(Commands::List { show }) => {
            println!("Listing entries (show: {show})");
        }
        Some(Commands::Remove { name, force }) => {
            println!("Removing entry: {name} (force: {force})");
        }
        Some(Commands::Generate { length, no_special }) => {
            println!("Generating password (length: {length}, no_special: {no_special})");
        }
        None => {
            println!("🥔 Welcome to Potato - Your secure password manager");
            println!("Run 'potato --help' for usage information.");
        }
    }

    Ok(())
}

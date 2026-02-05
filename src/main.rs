//! Potato - A secure CLI password manager
//!
//! This application provides a command-line interface for securely storing
//! and managing passwords and secrets using strong encryption.

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use copypasta::{ClipboardContext, ClipboardProvider};
use dialoguer::Confirm;
use potato::cli::{Cli, Commands};
use potato::storage;

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        eprintln!("{}", "Verbose mode enabled".dimmed());
    }

    let result = match cli.command {
        Some(Commands::Init { force }) => handle_init(force),
        Some(Commands::Add {
            name,
            username,
            url,
        }) => handle_add(name, username, url),
        Some(Commands::Get { name, copy }) => handle_get(&name, copy),
        Some(Commands::List { show }) => handle_list(show),
        Some(Commands::Remove { name, force }) => handle_remove(&name, force),
        Some(Commands::Generate { length, no_special }) => handle_generate(length, !no_special),
        None => {
            println!("{}", "🥔 Welcome to Potato - Your secure password manager".green().bold());
            println!("Run 'potato --help' for usage information.");
            Ok(())
        }
    };

    if let Err(e) = &result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }

    result
}

/// Handles the init command to create a new vault.
fn handle_init(force: bool) -> Result<()> {
    // Check if vault already exists
    if storage::vault_exists()? && !force {
        let path = storage::get_vault_path()?;
        eprintln!(
            "{} Vault already exists at {}",
            "Error:".red().bold(),
            path.display()
        );
        eprintln!("Use --force to overwrite.");
        std::process::exit(1);
    }

    println!("{}", "Initializing new password vault...".cyan());
    println!();

    // Get master password
    let password = rpassword::prompt_password("Enter master password: ")?;
    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    let confirm = rpassword::prompt_password("Confirm master password: ")?;
    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    // Initialize vault
    storage::init_vault(&password, force)?;

    let vault_path = storage::get_vault_path()?;
    println!();
    println!("{} Vault created at {}", "✓".green().bold(), vault_path.display());
    println!("{}", "Keep your master password safe - it cannot be recovered!".yellow());

    Ok(())
}

/// Handles the add command to add a new entry.
fn handle_add(name: String, username: Option<String>, url: Option<String>) -> Result<()> {
    // Get master password
    let master_password = rpassword::prompt_password("Master password: ")?;

    // Get entry password
    let use_generated = Confirm::new()
        .with_prompt("Generate a random password?")
        .default(true)
        .interact()?;

    let password = if use_generated {
        let generated = storage::generate_password(16, true);
        println!("{} {}", "Generated password:".green(), generated);
        generated
    } else {
        let pass = rpassword::prompt_password("Enter password: ")?;
        if pass.is_empty() {
            anyhow::bail!("Password cannot be empty");
        }
        pass
    };

    // Get optional notes
    let notes = dialoguer::Input::<String>::new()
        .with_prompt("Notes (optional)")
        .allow_empty(true)
        .interact_text()?;

    let notes = if notes.is_empty() { None } else { Some(notes) };

    // Add entry to vault
    storage::add_entry(&master_password, name.clone(), username, password, url, notes)?;

    println!();
    println!("{} Entry '{}' added successfully", "✓".green().bold(), name.cyan());

    Ok(())
}

/// Handles the get command to retrieve an entry.
fn handle_get(name: &str, copy: bool) -> Result<()> {
    let master_password = rpassword::prompt_password("Master password: ")?;

    let entry = storage::get_entry(&master_password, name)?;

    println!();
    println!("{}", format!("Entry: {}", entry.name).cyan().bold());
    println!("{}", "─".repeat(50).dimmed());

    if let Some(username) = &entry.username {
        println!("{}: {}", "Username".yellow(), username);
    }

    if let Some(url) = &entry.url {
        println!("{}: {}", "URL".yellow(), url);
    }

    if copy {
        // Copy to clipboard
        match ClipboardContext::new() {
            Ok(mut ctx) => {
                if ctx.set_contents(entry.password.clone()).is_ok() {
                    println!("{}: {} {}", "Password".yellow(), "********".dimmed(), "(copied to clipboard)".green());
                    println!();
                    println!("{}", "Clipboard will be cleared in 30 seconds...".yellow());

                    // Clear clipboard after 30 seconds
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_secs(30));
                        if let Ok(mut ctx) = ClipboardContext::new() {
                            let _ = ctx.set_contents(String::new());
                        }
                    });
                } else {
                    println!("{}: {}", "Password".yellow(), entry.password);
                    eprintln!("{}", "Warning: Failed to copy to clipboard".yellow());
                }
            }
            Err(_) => {
                println!("{}: {}", "Password".yellow(), entry.password);
                eprintln!("{}", "Warning: Clipboard not available".yellow());
            }
        }
    } else {
        println!("{}: {}", "Password".yellow(), entry.password);
    }

    if let Some(notes) = &entry.notes {
        println!("{}: {}", "Notes".yellow(), notes);
    }

    // Show timestamps
    let created = format_timestamp(entry.created_at);
    let modified = format_timestamp(entry.modified_at);
    println!();
    println!("{}: {}", "Created".dimmed(), created.dimmed());
    println!("{}: {}", "Modified".dimmed(), modified.dimmed());

    Ok(())
}

/// Handles the list command to show all entries.
fn handle_list(show_passwords: bool) -> Result<()> {
    let master_password = rpassword::prompt_password("Master password: ")?;

    let entries = storage::list_entries(&master_password)?;

    if entries.is_empty() {
        println!();
        println!("{}", "No entries found in vault.".yellow());
        println!("Use 'potato add' to add your first password.");
        return Ok(());
    }

    println!();
    println!("{} {}", "Vault contains".cyan(), format!("{} entries:", entries.len()).cyan().bold());
    println!();

    for entry in entries {
        println!("{}", format!("  • {}", entry.name).cyan().bold());

        if let Some(username) = &entry.username {
            println!("    {}: {}", "Username".dimmed(), username);
        }

        if let Some(url) = &entry.url {
            println!("    {}: {}", "URL".dimmed(), url);
        }

        if show_passwords {
            println!("    {}: {}", "Password".dimmed(), entry.password);
        }

        println!();
    }

    if !show_passwords {
        println!("{}", "Use --show flag to display passwords".dimmed());
    }

    Ok(())
}

/// Handles the remove command to delete an entry.
fn handle_remove(name: &str, force: bool) -> Result<()> {
    let master_password = rpassword::prompt_password("Master password: ")?;

    // Confirm deletion unless force flag is used
    if !force {
        let confirm = Confirm::new()
            .with_prompt(format!("Are you sure you want to delete '{}'?", name))
            .default(false)
            .interact()?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    storage::remove_entry(&master_password, name)?;

    println!();
    println!("{} Entry '{}' removed", "✓".green().bold(), name.cyan());

    Ok(())
}

/// Handles the generate command to create a random password.
fn handle_generate(length: usize, include_special: bool) -> Result<()> {
    let password = storage::generate_password(length, include_special);

    println!();
    println!("{}", "Generated password:".green().bold());
    println!();
    println!("  {}", password.cyan().bold());
    println!();

    // Try to copy to clipboard
    if let Ok(mut ctx) = ClipboardContext::new() {
        if ctx.set_contents(password).is_ok() {
            println!("{}", "✓ Copied to clipboard".green());
        }
    }

    Ok(())
}

/// Formats a Unix timestamp into a human-readable string.
fn format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);

    // Simple formatting - in production you'd use chrono
    match SystemTime::now().duration_since(datetime) {
        Ok(duration) => {
            let secs = duration.as_secs();
            if secs < 60 {
                format!("{} seconds ago", secs)
            } else if secs < 3600 {
                format!("{} minutes ago", secs / 60)
            } else if secs < 86400 {
                format!("{} hours ago", secs / 3600)
            } else {
                format!("{} days ago", secs / 86400)
            }
        }
        Err(_) => "just now".to_string(),
    }
}


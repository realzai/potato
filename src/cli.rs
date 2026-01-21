//! Command-line interface definitions using clap.

use clap::{Parser, Subcommand};

/// A secure, fast, and user-friendly CLI password manager.
#[derive(Debug, Parser)]
#[command(name = "potato")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize a new password vault
    Init {
        /// Force overwrite existing vault
        #[arg(short, long)]
        force: bool,
    },

    /// Add a new password entry
    Add {
        /// Name/identifier for the entry
        name: String,

        /// Username or email
        #[arg(short, long)]
        username: Option<String>,

        /// URL for the service
        #[arg(short = 'l', long)]
        url: Option<String>,
    },

    /// Get a password entry
    Get {
        /// Name of the entry to retrieve
        name: String,

        /// Copy password to clipboard
        #[arg(short, long)]
        copy: bool,
    },

    /// List all password entries
    List {
        /// Show passwords in plain text
        #[arg(short, long)]
        show: bool,
    },

    /// Remove a password entry
    Remove {
        /// Name of the entry to remove
        name: String,

        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },

    /// Generate a random password
    Generate {
        /// Length of the password
        #[arg(short, long, default_value = "16")]
        length: usize,

        /// Exclude special characters
        #[arg(short, long)]
        no_special: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_without_args() {
        let cli = Cli::parse_from(["potato"]);
        assert!(!cli.verbose);
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_verbose_flag() {
        let cli = Cli::parse_from(["potato", "--verbose"]);
        assert!(cli.verbose);
    }

    #[test]
    fn cli_parses_init_command() {
        let cli = Cli::parse_from(["potato", "init"]);
        assert!(matches!(cli.command, Some(Commands::Init { force: false })));
    }

    #[test]
    fn cli_parses_init_with_force() {
        let cli = Cli::parse_from(["potato", "init", "--force"]);
        assert!(matches!(cli.command, Some(Commands::Init { force: true })));
    }

    #[test]
    fn cli_parses_add_command() {
        let cli = Cli::parse_from(["potato", "add", "github", "-u", "user@example.com"]);
        if let Some(Commands::Add { name, username, .. }) = cli.command {
            assert_eq!(name, "github");
            assert_eq!(username, Some("user@example.com".to_string()));
        } else {
            panic!("Expected Add command");
        }
    }

    #[test]
    fn cli_parses_get_command() {
        let cli = Cli::parse_from(["potato", "get", "github", "--copy"]);
        if let Some(Commands::Get { name, copy }) = cli.command {
            assert_eq!(name, "github");
            assert!(copy);
        } else {
            panic!("Expected Get command");
        }
    }

    #[test]
    fn cli_parses_list_command() {
        let cli = Cli::parse_from(["potato", "list", "--show"]);
        assert!(matches!(cli.command, Some(Commands::List { show: true })));
    }

    #[test]
    fn cli_parses_generate_command() {
        let cli = Cli::parse_from(["potato", "generate", "-l", "24", "--no-special"]);
        if let Some(Commands::Generate { length, no_special }) = cli.command {
            assert_eq!(length, 24);
            assert!(no_special);
        } else {
            panic!("Expected Generate command");
        }
    }

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}

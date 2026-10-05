use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Inspect Askar storage without modifying the source database")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Export decrypted items to a plaintext SQLite database.
    Export {
        /// Askar SQLite or PostgreSQL URI.
        #[arg(long, env = "ASKAR_EXPLORER_URI")]
        uri: String,
        /// New plaintext SQLite file to create.
        #[arg(long, env = "ASKAR_EXPLORER_OUT")]
        out: PathBuf,
        /// Include key-manager entries, which may contain private keys.
        #[arg(long)]
        include_kms: bool,
        /// Read the store pass key from this environment variable instead of prompting.
        #[arg(long)]
        pass_key_env: Option<String>,
    },
    /// Preview or apply edits made to a decrypted export.
    Apply {
        /// Source Askar store URI.
        #[arg(long, env = "ASKAR_EXPLORER_URI")]
        uri: String,
        /// Editable SQLite export file.
        #[arg(long, env = "ASKAR_EXPLORER_OUT")]
        edits: PathBuf,
        /// Write changes to Askar; without this flag only a plan is printed.
        #[arg(long, requires = "confirm_backup")]
        commit: bool,
        /// Confirm that a recoverable backup of the source store exists.
        #[arg(long)]
        confirm_backup: bool,
        /// Read the store pass key from this environment variable instead of prompting.
        #[arg(long)]
        pass_key_env: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    if Path::new(".env").exists() {
        dotenvy::from_path(".env").context("Cannot load .env")?;
    }
    let Args { command } = Args::parse();
    match command {
        Command::Export {
            uri,
            out,
            include_kms,
            pass_key_env,
        } => askar_explorer::export(&uri, &out, include_kms, pass_key_env.as_deref()).await,
        Command::Apply {
            uri,
            edits,
            commit,
            pass_key_env,
            ..
        } => askar_explorer::apply::run(&uri, &edits, commit, pass_key_env.as_deref()).await,
    }
}

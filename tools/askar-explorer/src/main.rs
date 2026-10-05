use std::{
    io::stdout,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use askar_explorer::{
    commands::{self, Format, ListOptions},
    describe::DescribeOptions,
    redact::{Policy, Redactor, View},
    source::{Query, Source, TagCondition},
};
use askar_storage::inspect::ExpiryFilter;
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "Inspect Askar storage without modifying the source database")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

/// Connection and output options shared by the read commands.
#[derive(ClapArgs)]
struct Connection {
    /// Askar SQLite or PostgreSQL URI.
    #[arg(long, env = "ASKAR_EXPLORER_URI")]
    uri: String,
    /// Read the store pass key from this environment variable instead of prompting.
    #[arg(long)]
    pass_key_env: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t)]
    format: Format,
}

/// How much of the data a command may show.
#[derive(ClapArgs)]
struct Visibility {
    /// Show real values and tag values (key-manager values stay hidden).
    #[arg(long, conflicts_with = "redact")]
    reveal: bool,
    /// Show only shapes and pseudonyms allowed by the policy; this is the view for AI agents.
    #[arg(long)]
    redact: bool,
    /// Redaction policy file used with --redact.
    #[arg(long, env = "ASKAR_EXPLORER_POLICY")]
    policy: Option<PathBuf>,
}

impl Visibility {
    fn view(&self) -> Result<View> {
        Ok(if self.redact {
            View::Redacted(Arc::new(Redactor::open(self.policy.as_deref())?))
        } else if self.reveal {
            View::Reveal
        } else {
            View::Hidden
        })
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    Item,
    Kms,
    Any,
}

#[derive(Clone, Copy, ValueEnum)]
enum ExpiryArg {
    Any,
    Live,
    Expired,
}

#[derive(Subcommand)]
enum Command {
    /// List profiles and whether their keys unlock.
    Profiles {
        #[command(flatten)]
        connection: Connection,
    },
    /// Count entries per category without showing any values.
    Stats {
        #[command(flatten)]
        connection: Connection,
        /// Only this profile.
        #[arg(long)]
        profile: Option<String>,
    },
    /// List entries; filters on category, name and tags run in the database.
    Ls {
        #[command(flatten)]
        connection: Connection,
        /// Only this profile.
        #[arg(long)]
        profile: Option<String>,
        /// Exact category.
        #[arg(long)]
        category: Option<String>,
        /// Exact entry name.
        #[arg(long)]
        name: Option<String>,
        /// Encrypted tag that must equal name=value (repeatable).
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Plaintext tag that must equal name=value (repeatable).
        #[arg(long = "ptag")]
        plaintext_tags: Vec<String>,
        /// Which kind of entries to list.
        #[arg(long, value_enum, default_value = "item")]
        kind: KindArg,
        /// Which entries to list by expiry.
        #[arg(long, value_enum, default_value = "any")]
        expiry: ExpiryArg,
        /// Maximum number of entries.
        #[arg(long, default_value_t = 50)]
        limit: i64,
        /// Continue after this entry id.
        #[arg(long, default_value_t = 0)]
        after_id: i64,
        #[command(flatten)]
        visibility: Visibility,
    },
    /// Show one entry by id.
    Get {
        #[command(flatten)]
        connection: Connection,
        /// Profile name; optional when the store has one profile.
        #[arg(long)]
        profile: Option<String>,
        /// Entry id, as shown by `ls`.
        #[arg(long)]
        id: i64,
        #[command(flatten)]
        visibility: Visibility,
    },
    /// Summarize the structure of one category: fields, types, counts and tags.
    Describe {
        #[command(flatten)]
        connection: Connection,
        /// Category to describe.
        category: String,
        /// Only this profile.
        #[arg(long)]
        profile: Option<String>,
        /// How many entries to inspect, in id order.
        #[arg(long, default_value_t = 500)]
        sample: usize,
        /// Policy file listing which values may be shown.
        #[arg(long, env = "ASKAR_EXPLORER_POLICY")]
        policy: Option<PathBuf>,
    },
    /// Run a read-only SQL query against the `items` table.
    Sql {
        #[command(flatten)]
        connection: Connection,
        /// A single SELECT statement, e.g. "SELECT category, count(*) FROM items GROUP BY 1".
        query: String,
        #[command(flatten)]
        visibility: Visibility,
        /// Maximum number of result rows.
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
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
        Command::Profiles { connection } => {
            let source = Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            commands::profiles(&source, &mut stdout().lock(), connection.format)
        }
        Command::Stats {
            connection,
            profile,
        } => {
            let mut source =
                Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            commands::stats(
                &mut source,
                profile.as_deref(),
                &mut stdout().lock(),
                connection.format,
            )
            .await
        }
        Command::Ls {
            connection,
            profile,
            category,
            name,
            tags,
            plaintext_tags,
            kind,
            expiry,
            limit,
            after_id,
            visibility,
        } => {
            let view = visibility.view()?;
            let mut conditions = Vec::new();
            for spec in &tags {
                conditions.push(TagCondition::parse(spec, false)?);
            }
            for spec in &plaintext_tags {
                conditions.push(TagCondition::parse(spec, true)?);
            }
            let query = Query {
                id: None,
                kind: match kind {
                    KindArg::Item => Some(2),
                    KindArg::Kms => Some(1),
                    KindArg::Any => None,
                },
                category,
                name,
                tags: conditions,
                expiry: match expiry {
                    ExpiryArg::Any => ExpiryFilter::Any,
                    ExpiryArg::Live => ExpiryFilter::LiveOnly,
                    ExpiryArg::Expired => ExpiryFilter::ExpiredOnly,
                },
            };
            let mut source =
                Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            let options = ListOptions {
                profile,
                query,
                limit,
                after_id,
                view,
            };
            commands::list(
                &mut source,
                &options,
                &mut stdout().lock(),
                connection.format,
            )
            .await
        }
        Command::Get {
            connection,
            profile,
            id,
            visibility,
        } => {
            let view = visibility.view()?;
            let mut source =
                Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            let mut selected = source.select_profiles(profile.as_deref())?;
            if selected.len() != 1 {
                bail!("The store has several profiles; choose one with --profile");
            }
            let profile = selected.remove(0);
            commands::get(
                &mut source,
                &profile,
                id,
                &view,
                &mut stdout().lock(),
                connection.format,
            )
            .await
        }
        Command::Describe {
            connection,
            category,
            profile,
            sample,
            policy,
        } => {
            let policy = Policy::load(
                policy
                    .as_deref()
                    .unwrap_or_else(|| Path::new(".askar-explorer/policy.toml")),
            )?;
            let mut source =
                Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            let options = DescribeOptions { profile, sample };
            let description =
                askar_explorer::describe::describe(&mut source, &category, &options, &policy)
                    .await?;
            commands::print_rows(
                description.columns,
                description.rows,
                &mut stdout().lock(),
                connection.format,
            )
        }
        Command::Sql {
            connection,
            query,
            visibility,
            limit,
        } => {
            let view = visibility.view()?;
            let source = Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            let source = Arc::new(tokio::sync::Mutex::new(source));
            let result = askar_explorer::sql::query(source, query, view, limit).await?;
            commands::print_rows(
                result.columns,
                result.rows,
                &mut stdout().lock(),
                connection.format,
            )?;
            if result.truncated {
                eprintln!("Output stopped at {limit} rows; raise --limit to see more.");
            }
            Ok(())
        }
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

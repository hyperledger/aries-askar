//! Read commands that print live store contents as a table or JSON lines.

use std::io::Write;

use anyhow::{bail, Result};
use askar_storage::{entry::EntryTag, inspect::InspectedItem};
use clap::ValueEnum;
use serde_json::{json, Value};

use crate::source::{Profile, Query, Source};

const MAX_CELL: usize = 60;
const PAGE: i64 = 500;

/// How results are printed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Aligned columns for people.
    #[default]
    Table,
    /// One JSON object per line, for scripts.
    Jsonl,
}

/// Options for [`list`].
#[derive(Debug)]
pub struct ListOptions {
    /// Profile name; all profiles when unset.
    pub profile: Option<String>,
    /// Conditions evaluated by the database.
    pub query: Query,
    /// Maximum number of rows in total.
    pub limit: i64,
    /// Continue after this row ID (applies to each profile).
    pub after_id: i64,
    /// Show values and tag values.
    pub reveal: bool,
}

struct Table {
    columns: Vec<&'static str>,
    rows: Vec<Vec<Value>>,
}

impl Table {
    fn new(columns: &[&'static str]) -> Self {
        Self {
            columns: columns.to_vec(),
            rows: Vec::new(),
        }
    }

    fn write(&self, out: &mut dyn Write, format: Format) -> Result<()> {
        match format {
            Format::Jsonl => {
                for row in &self.rows {
                    let object: serde_json::Map<String, Value> = self
                        .columns
                        .iter()
                        .map(|column| (*column).to_owned())
                        .zip(row.iter().cloned())
                        .collect();
                    writeln!(out, "{}", Value::Object(object))?;
                }
            }
            Format::Table => {
                let cells: Vec<Vec<String>> = self
                    .rows
                    .iter()
                    .map(|row| row.iter().map(|value| cell(value, MAX_CELL)).collect())
                    .collect();
                let widths: Vec<usize> = self
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(index, column)| {
                        cells
                            .iter()
                            .map(|row| row[index].chars().count())
                            .chain([column.chars().count()])
                            .max()
                            .unwrap_or_default()
                    })
                    .collect();
                let line = |out: &mut dyn Write, row: Vec<&str>| -> Result<()> {
                    let padded: Vec<String> = row
                        .iter()
                        .zip(&widths)
                        .map(|(text, width)| format!("{text:<width$}"))
                        .collect();
                    writeln!(out, "{}", padded.join("  ").trim_end())?;
                    Ok(())
                };
                line(out, self.columns.to_vec())?;
                for row in &cells {
                    line(out, row.iter().map(String::as_str).collect())?;
                }
            }
        }
        Ok(())
    }
}

fn cell(value: &Value, max: usize) -> String {
    let text = match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| cell(item, usize::MAX))
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    };
    let text = text.replace(['\n', '\r', '\t'], " ");
    if text.chars().count() > max {
        let kept: String = text.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    } else {
        text
    }
}

fn kind_label(kind: i64) -> &'static str {
    match kind {
        1 => "kms",
        2 => "item",
        _ => "unknown",
    }
}

fn text_or_marker(result: &Result<String, askar_storage::Error>) -> Value {
    match result {
        Ok(text) => json!(text),
        Err(_) => json!("<undecryptable>"),
    }
}

fn describe_value(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => format!("0x{}", hex_string(bytes)),
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn errors(item: &InspectedItem) -> Vec<Value> {
    let mut errors = Vec::new();
    let mut note = |field: &str, error: Option<&askar_storage::Error>| {
        if let Some(error) = error {
            errors.push(json!(format!("{field}: {error}")));
        }
    };
    note("category", item.category.as_ref().err());
    note("name", item.name.as_ref().err());
    note("value", item.value.as_ref().err());
    for tag in &item.tags {
        note("tag", tag.as_ref().err());
    }
    errors
}

fn tags(item: &InspectedItem, reveal: bool) -> Vec<Value> {
    item.tags
        .iter()
        .filter_map(|tag| tag.as_ref().ok())
        .map(|tag| {
            let (name, value, plaintext) = match tag {
                EntryTag::Plaintext(name, value) => (name, value, true),
                EntryTag::Encrypted(name, value) => (name, value, false),
            };
            let label = if plaintext {
                format!("~{name}")
            } else {
                name.clone()
            };
            json!(if reveal {
                format!("{label}={value}")
            } else {
                label
            })
        })
        .collect()
}

/// Value text for display; key-manager values are never shown.
fn value_text(item: &InspectedItem) -> Value {
    if item.kind == 1 {
        return json!("<key material hidden>");
    }
    match &item.value {
        Ok(value) => json!(describe_value(value)),
        Err(_) => json!("<undecryptable>"),
    }
}

fn expiry(item: &InspectedItem) -> Value {
    item.expiry
        .map_or(Value::Null, |expiry| json!(expiry.to_string()))
}

fn value_bytes(item: &InspectedItem) -> Value {
    item.value
        .as_ref()
        .map_or(Value::Null, |value| json!(value.len()))
}

/// Print the store's profiles and whether their keys unlocked.
pub fn profiles(source: &Source, out: &mut dyn Write, format: Format) -> Result<()> {
    let mut table = Table::new(&["id", "profile", "key"]);
    for profile in source.select_profiles(None)? {
        table.rows.push(vec![
            json!(profile.id),
            json!(profile.name),
            json!(profile.key_error().unwrap_or("ok")),
        ]);
    }
    table.write(out, format)
}

/// Print row counts and encrypted value sizes per category.
pub async fn stats(
    source: &mut Source,
    profile: Option<&str>,
    out: &mut dyn Write,
    format: Format,
) -> Result<()> {
    if let Some(name) = profile {
        source.select_profiles(Some(name))?;
    }
    let mut table = Table::new(&["profile", "kind", "category", "items", "expired", "bytes"]);
    for stat in source.stats().await? {
        if profile.is_some_and(|name| name != stat.profile) {
            continue;
        }
        table.rows.push(vec![
            json!(stat.profile),
            json!(kind_label(stat.kind)),
            json!(stat.category),
            json!(stat.items),
            json!(stat.expired),
            json!(stat.encrypted_value_bytes),
        ]);
    }
    table.write(out, format)
}

/// Print matching entries, up to the limit.
pub async fn list(
    source: &mut Source,
    options: &ListOptions,
    out: &mut dyn Write,
    format: Format,
) -> Result<()> {
    if options.limit <= 0 {
        bail!("The limit must be positive");
    }
    let mut columns = vec![
        "profile",
        "id",
        "kind",
        "category",
        "name",
        "value_bytes",
        "expiry",
        "tags",
        "errors",
    ];
    if options.reveal {
        columns.push("value");
    }
    let mut table = Table::new(&columns);
    let mut remaining = options.limit;
    for profile in source.select_profiles(options.profile.as_deref())? {
        let mut after_id = options.after_id;
        while remaining > 0 {
            let page = source
                .scan(&profile, &options.query, after_id, remaining.min(PAGE))
                .await?;
            let Some(last) = page.last() else { break };
            after_id = last.id;
            remaining -= page.len() as i64;
            for item in &page {
                let mut row = vec![
                    json!(profile.name),
                    json!(item.id),
                    json!(kind_label(item.kind)),
                    text_or_marker(&item.category),
                    text_or_marker(&item.name),
                    value_bytes(item),
                    expiry(item),
                    Value::Array(tags(item, options.reveal)),
                    Value::Array(errors(item)),
                ];
                if options.reveal {
                    row.push(value_text(item));
                }
                table.rows.push(row);
            }
        }
    }
    table.write(out, format)
}

fn pretty(text: &str) -> String {
    serde_json::from_str::<Value>(text)
        .and_then(|value| serde_json::to_string_pretty(&value))
        .unwrap_or_else(|_| text.to_owned())
}

/// Print one entry in full, hiding values unless `reveal` is set.
pub async fn get(
    source: &mut Source,
    profile: &Profile,
    id: i64,
    reveal: bool,
    out: &mut dyn Write,
    format: Format,
) -> Result<()> {
    let Some(item) = source.fetch(profile, id).await? else {
        bail!("No entry with id {id} in profile {}", profile.name);
    };
    let value = if reveal {
        value_text(&item)
    } else {
        json!(format!(
            "<{} bytes; use --reveal to show>",
            item.value.as_ref().map_or(0, |value| value.len())
        ))
    };
    let tag_list = tags(&item, reveal);
    let error_list = errors(&item);
    match format {
        Format::Jsonl => {
            let object = json!({
                "profile": profile.name,
                "id": item.id,
                "kind": kind_label(item.kind),
                "category": text_or_marker(&item.category),
                "name": text_or_marker(&item.name),
                "expiry": expiry(&item),
                "tags": tag_list,
                "errors": error_list,
                "value": value,
            });
            writeln!(out, "{object}")?;
        }
        Format::Table => {
            writeln!(out, "profile:  {}", profile.name)?;
            writeln!(out, "id:       {}", item.id)?;
            writeln!(out, "kind:     {}", kind_label(item.kind))?;
            writeln!(
                out,
                "category: {}",
                cell(&text_or_marker(&item.category), usize::MAX)
            )?;
            writeln!(
                out,
                "name:     {}",
                cell(&text_or_marker(&item.name), usize::MAX)
            )?;
            writeln!(out, "expiry:   {}", cell(&expiry(&item), usize::MAX))?;
            writeln!(
                out,
                "tags:     {}",
                cell(&Value::Array(tag_list), usize::MAX)
            )?;
            for error in &error_list {
                writeln!(out, "error:    {}", cell(error, usize::MAX))?;
            }
            let shown = value.as_str().map(pretty).unwrap_or_default();
            writeln!(out, "value:\n{shown}")?;
        }
    }
    Ok(())
}

# Askar Explorer

Inspect and troubleshoot Askar SQLite or PostgreSQL stores. Explorer can browse a
live store from the CLI or browser, query it with read-only SQL, provide an
agent-safe redacted API and MCP server, and export a **plaintext SQLite database**
for DBeaver or another SQL client. Source connections are read-only except when
you explicitly apply a reviewed change set or edited export. Key-manager (KMS)
records are excluded from exports unless explicitly requested and are never
revealed by the browser.

## Export

From the repository root:

```sh
cargo run -p askar-explorer -- export \
  --uri 'sqlite:///path/to/store.db' --out ./inspection.db
```

For PostgreSQL, use an Askar URI such as
`postgres://user:password@host:5432/database?schema=wallet_schema`. To avoid
exposing connection credentials in shell history or process arguments, put the
URI in `.env` instead (see below). The command prompts for the store pass key
unless the key method is `none` or a pass key environment variable is set.
The output file must not already exist.

To include private key material, add `--include-kms` explicitly. Handle that
export with particular care.

## Browse a live store

These commands read the store directly (read-only) and decrypt as they go, so
they need no export file. They use the same `--uri`, `.env` and pass key
handling as `export`:

```sh
askar-explorer profiles                      # profiles and whether their keys unlock
askar-explorer stats                         # entries, expired rows and bytes per category
askar-explorer ls --category connections --limit 20
askar-explorer ls --ptag state=active        # plaintext tag equal to a value
askar-explorer ls --tag owner=alice          # encrypted tag, exact match only
askar-explorer ls --expiry expired           # rows Askar's normal reads skip
askar-explorer get --id 42 --reveal          # one entry in full
```

Add `--format jsonl` for one JSON object per line. `ls` pages by entry id: pass
the last id you saw as `--after-id` to continue. Add `--profile NAME` when the
store has several profiles.

Filters on category, name and tags are encrypted and evaluated by the database,
so they stay fast on large stores. Anything that depends on the *contents* of a
value still requires decrypting rows. Values and tag values are hidden unless
you pass `--reveal`, and key-manager (KMS) values are never printed; use
`export --include-kms` if you need those. Entries are listed as `item` by
default; use `--kind kms` or `--kind any` to include key-manager entries.

## SQL over a live store

`askar-explorer sql` runs one read-only `SELECT` against a virtual `items` table
that decrypts rows as SQLite asks for them, so you can query the store as if it
were unencrypted:

```sh
askar-explorer sql "SELECT category, count(*) AS n FROM items GROUP BY category ORDER BY n DESC"
askar-explorer sql --reveal "SELECT name, json_extract(value, '\$.state') AS state
                             FROM items WHERE category = 'connections' LIMIT 20"
askar-explorer sql "SELECT name FROM items WHERE ptag = 'state=active' AND etag = 'owner=alice'"
```

Columns: `profile`, `id`, `kind` (`item` or `kms`), `category`, `name`, `value`,
`value_bytes`, `expiry`, `ptags` and `etags` (JSON objects of the plaintext and
encrypted tags), and `errors` (JSON, set when a field could not be decrypted).
Output is a table, or JSON lines with `--format jsonl`; `--limit` (default
1000) caps the rows printed.

**What is fast.** Equality conditions on `profile`, `id`, `kind`, `category`,
`name` and the hidden columns `ptag` and `etag` (both written `'name=value'`) are
encrypted and evaluated by the database, using its indexes. `expiry_mode`
(`any`, `live` or `expired`) selects rows by expiry; expired rows are included
by default. **Everything else is evaluated after decryption**, for example
`json_extract(value, ...)`, `LIKE`, ranges and `GROUP BY` on values. On a very
large profile those read and decrypt every row, so combine them with an
equality condition on `category` where you can. A `LIMIT` stops reading early
when no sort or grouping is needed.

**What is hidden.** `value`, and the values inside `ptags` and `etags`, are
NULL unless you pass `--reveal`; key-manager values are always NULL.

**Safeguards.** The statement runs in a throwaway in-memory SQLite connection
whose authorizer allows only reads and functions, so `CREATE`, `DROP`, `ATTACH`,
`PRAGMA` and writes are rejected, and only one statement is accepted. The store
itself is opened read-only.

## Understand a category

`describe` summarizes what one category looks like, so you (or an agent) can plan
queries without reading entries:

```sh
askar-explorer describe connections --sample 1000
```

It prints counts for the whole category (entries, expired), facts about the
sampled entries (JSON documents, plain-text and binary values, size range), and
one row per JSON path and per tag:

| column | meaning |
| --- | --- |
| `types` | JSON types seen at the path (`string`, `number`, `object`, ...) or the tag kind |
| `count`, `present_pct` | occurrences, and the share of documents (or entries, for tags) that have it |
| `distinct` | number of different values, so you can spot identifiers versus enumerations |
| `length` | string length range, or array size range |
| `values` | the most common values with counts, **only** for paths and tags the policy lists |

Object keys that look like identifiers are grouped under `*`, as in `*.status`.
The command decrypts values in memory but prints only these aggregates, so it is
safe to hand to an agent; the same `policy.toml` as `--redact` controls which values
are shown. Booleans are always shown. The sample is the first `--sample` entries by id,
not a random draw, so check `entries` against `sampled` before generalizing.

## Agent API

`askar-explorer serve` runs a small HTTP API for AI agents. It opens the
store with the pass key and **always** applies the redacted view: requests cannot
choose another view, nothing in it writes to the store, and unknown request fields are
rejected. The only thing an agent can add is a [proposal](#change-sets-proposing-and-applying-fixes)
that a person reviews.

```sh
askar-explorer serve --uri "$ASKAR_EXPLORER_URI" --policy ~/.askar-explorer/policy.toml \
  --agent-listen 0.0.0.0:7071 --token-file /run/explorer/agent.token
```

Clients send `Authorization: Bearer <token>`; the token is regenerated on each start
and written to `--token-file` (mode 0644, since it only unlocks the redacted view).
For a container without a terminal, give the pass key through
`ASKAR_EXPLORER_PASS_KEY_FILE` (a file such as a Docker secret) instead of a prompt.

| Route | Purpose |
| --- | --- |
| `GET /v1/profiles`, `GET /v1/stats` | profiles; entries and sizes per category |
| `POST /v1/describe` `{category, profile?, sample?}` | structure of a category |
| `POST /v1/query` `{sql, limit?}` | read-only SQL on the redacted `items` table |
| `POST /v1/entries` `{category?, profile?, kind?, expiry?, tags?, plaintext_tags?, limit?, after_id?}` | list entries |
| `POST /v1/entry` `{id, profile?}` | one entry |
| `POST /v1/proposals` `{title, rationale?, ops}` | save a proposal; returns its id and the command a person runs to review it |
| `GET /v1/proposals` | each proposal's id, title, status and size |

The server keeps proposals in `--proposals` (`ASKAR_EXPLORER_PROPOSALS`). There is no route
that applies, rejects, reads or deletes one. `ASKAR_EXPLORER_REVIEW_COMMAND` (optional) is
the text placed before `changes show <id>` in the reply, so an agent can tell you what to run.

Responses are `{"columns": [...], "rows": [[...]]}` (`/v1/entry` returns an object).
Limits apply: 1000 SQL rows, 200 listed entries, a 5000 entry sample, 64 KB request
bodies and a 60 second timeout.

**Keep the policy and pseudonym key where agents cannot write.** The server reads
the policy once at startup; if an agent could edit that file it could list any path
as shown and restart the server. Likewise, do not give agents the pass key, the
database credentials or a way to run the explorer with `--reveal`.

## MCP server for agents

`askar-explorer mcp` speaks the Model Context Protocol on stdio, so an AI agent (for
example VS Code's agent mode) can use the store as a set of tools. It holds no keys and
no data: each tool call is forwarded to the agent API, which applies the redacted view.

```sh
askar-explorer mcp --agent-url http://explorer:7071 --token-file /run/explorer/agent.token
```

Tools: `list_profiles`, `category_stats`, `describe_category`, `query`, `list_entries`,
`get_entry`, `propose_change` and `list_proposals`. The first six only read. `propose_change`
saves a proposal for a person; no tool applies changes or reveals values.
A suggested flow for an agent is `category_stats`, then `describe_category` for a category
of interest, then `query`. Errors, such as a refused filter or a rejected statement, come
back as tool errors the agent can read. The token file is read on every call, so a
restarted server's new token is picked up without restarting the agent.

To register it in VS Code outside a dev container, add a stdio server to `mcp.json` that
runs the command above. Inside the dev container this is configured for you (see below).

## Redacted view for AI agents

`ls`, `get` and `sql` take `--redact` to show structure and patterns without data.
This is the view to give an AI agent or anyone else who should understand a store
without reading it:

```sh
askar-explorer ls --redact --category connections --limit 5
askar-explorer sql --redact "SELECT json_extract(value,'\$.state') AS state, count(*) FROM items
                             WHERE category='connections' GROUP BY 1"
```

- **Values** are reduced to their JSON shape: `{"state": "<string:6>", "age": "<number>"}`.
  Booleans and nulls are shown; text that is not JSON shows its length; binary
  shows its size. Key-manager values are never shown.
- **Entry names and tag values** become stable pseudonyms such as `p-3fa9c1d07b2e`:
  equal values get equal tokens, so you can see that two entries share an owner
  without learning who it is.
- **Object keys** stay when they look like field names. Keys that look like
  identifiers (DIDs, UUIDs, long encoded strings) are pseudonymized too.
- **Filters that would let a reader test guesses** are refused: `--name`, and
  tag filters on tags the policy does not list.
- `category`, tag names, sizes, expiry and counts are visible; `stats` therefore
  needs no flag.

Choose what may be shown in `.askar-explorer/policy.toml` (or `--policy FILE`, or
`ASKAR_EXPLORER_POLICY`). Without a file nothing but shapes and pseudonyms is shown:

```toml
show_tags = ["state"]                 # tag values that may be shown and filtered on
show_paths = ["state", "role"]        # JSON paths whose values may be shown
pseudonymize_paths = ["owner"]        # string values replaced by pseudonyms
safe_keys = ["connection_id"]         # keys that are field names, not data

[category.connections]                # additions for one category
show_paths = ["created_at", "items[].status"]
```

Paths are dot-separated, with `[]` for array elements and `*` for a pseudonymized
key (so `*.status` matches `status` under any identifier key). The pseudonym key
is created in `.askar-explorer/pseudonym.key` on first use, readable only by you
and ignored by git; delete it to make all existing pseudonyms unlinkable.

**This is a guardrail, not a security boundary.** It protects data from a reader
that can only call these commands. A process that can also run the explorer with
the pass key, or read the database and key files, can use `--reveal`. Detection of
identifier-like keys is heuristic, so review a sample of the redacted output before
handing it over, and list sensitive field names rather than relying on defaults.

## Web interface

`askar-explorer ui` serves a browser interface for you, not for agents. It shows **real,
decrypted data**, so it starts locked and asks for the store pass key before showing
anything (a store without a pass key gets a one-time login code, printed only in the
service's output).

```sh
askar-explorer ui --uri "$ASKAR_EXPLORER_URI"        # http://127.0.0.1:7070
```

Today it offers a dashboard (profiles and categories) and read-only browsing: filter
entries by profile, category, exact name, tags, kind and expiry, and open one entry to see
its decoded value, tags and any decryption problems. Key-manager values are never shown.
Editing, a SQL console and the proposals inbox are not in the browser yet; use the commands
above for those.

What protects it:

- **The pass key is the boundary.** Anything that can reach the port, such as an agent in
  the dev container going through `host.docker.internal`, can load the login form but
  cannot get past it. The `Host` check below does not stop a program, which can forge it.
- Five wrong logins lock logins out for a minute, then two, four and so on up to an hour;
  a successful login clears this. An attacker can keep you locked out the same way;
  restarting the service resets it.
- One session at a time, in an `HttpOnly`, `SameSite=Strict` cookie. A new login replaces
  the old session, **Lock** ends it, and it ends by itself after `--idle-seconds` (default
  900) of inactivity. The keys are dropped from memory when it ends.
- Requests need an expected `Host` header (default `localhost:PORT` and `127.0.0.1:PORT`;
  change with `--allowed-host`), which defeats DNS rebinding from a web page, and
  cross-origin posts are refused.
- Pages are rendered on the server with automatic escaping, contain no scripts, and carry a
  strict Content-Security-Policy and `Cache-Control: no-store`.

It uses plain HTTP and is meant for the loopback interface. In the dev container setup:

```sh
docker compose -f .devcontainer/compose.yaml --profile explorer-ui up -d --build explorer-ui
```

then open http://localhost:7070. The `explorer-ui` service reads the same
`~/.askar-explorer/explorer.env` as the agent service, but does not mount the host config
directory or the `pass.key` file. The pass key is entered in the browser login form. The
service is published on the host's loopback only and sits on a network the dev container is
not attached to; the host port can still be reached from that container, so protect the UI
with the pass key. Because it is on its own network, it cannot reach the Compose `postgres`
service by name; for a database on your machine use `host.docker.internal` in the URI.
Stop it with `docker compose -f .devcontainer/compose.yaml --profile explorer-ui stop explorer-ui`.

## Change sets: proposing and applying fixes

Agents never change data. They can only *propose* edits, and a person decides. A proposal
lists edits by profile name and entry id, as shown by `ls`:

```json
{"title": "Close stuck connections", "rationale": "State is 'active' but they expired in March",
 "ops": [
   {"op": "set_json", "profile": "main", "id": 12, "pointer": "/state", "value": "completed"},
   {"op": "set_tag", "profile": "main", "id": 12, "name": "state", "value": "completed", "plaintext": true},
   {"op": "remove_tag", "profile": "main", "id": 12, "name": "owner"},
   {"op": "set_expiry", "profile": "main", "id": 12, "expiry": "2030-01-01 00:00:00"},
   {"op": "remove", "profile": "main", "id": 13},
   {"op": "insert", "profile": "main", "category": "connections", "name": "new-one", "value": {"state": "new"}}
 ]}
```

`set_json` takes an RFC 6901 JSON Pointer (`/a/0/b`; an empty pointer replaces the whole
value). It replaces an existing value or adds a key to an existing object, and keeps the
order of the other fields. Removing an entry cannot be combined with other edits to it.
Key-manager entries and expired entries cannot be changed.

A proposal file records the edits and a fingerprint of each entry it was based on, but
**never the old values**. Creating a proposal tells the author nothing about the data: a
guessed name or value that already exists, or an edit that changes nothing, is accepted
silently, so proposals cannot be used to test guesses. Proposals are limited to 100 edits,
256 KB of new values and 50 waiting at a time.

You review and apply them with the pass key, from where the explorer runs:

```sh
askar-explorer changes list
askar-explorer changes show p-3fa9c1d07b2e        # the real before and after of every change
askar-explorer changes apply p-3fa9c1d07b2e       # dry run: shows what would be written
askar-explorer changes apply p-3fa9c1d07b2e --commit --confirm-backup
askar-explorer changes reject p-3fa9c1d07b2e
```

Applying is deliberately hard to automate and to do by accident:

- It needs a **write connection** in `ASKAR_EXPLORER_WRITE_URI` (or `--write-uri`), separate
  from the read-only `ASKAR_EXPLORER_URI`, and it must point at the same store.
- It needs `--confirm-backup`, so take a backup first (`pg_dump`, or copy the SQLite file).
- It needs an **interactive terminal** where you type the proposal id. A script or an
  agent cannot answer it.
- Every entry must be unchanged since the proposal was made; otherwise nothing is written.
- Changes are written through Askar's encryption in one transaction per profile.

Proposals live in `--proposals` (`ASKAR_EXPLORER_PROPOSALS`, default
`.askar-explorer/proposals`); `changes.log` there records each decision without values.

## Dev container with an agent boundary

The dev container (see `.devcontainer/`) is where agents work, so it is built **not** to
hold the pass key, the database credentials, the policy or any plaintext. The explorer
runs as a separate, opt-in service that does hold them:

| | dev container (agents) | `explorer` service (you start it) |
| --- | --- | --- |
| pass key, database URI, policy, pseudonym key | never mounted | mounted from your host |
| agent token | read-only | writes it |
| proposals | never mounted | its own volume, where agents' proposals are kept |
| Docker socket, exports | none | none |
| network | outbound, and `http://explorer:7071` | outbound to your database; port 7071 is not published to the host |

Set it up once on your host (not inside the workspace):

```sh
mkdir -p ~/.askar-explorer && chmod 700 ~/.askar-explorer
cd ~/.askar-explorer
echo 'ASKAR_EXPLORER_URI=postgres://readonly_user:secret@db.example.com:5432/mediator?sslmode=require' > explorer.env
printf 'show_tags = ["state"]\nshow_paths = ["state", "role"]\n' > policy.toml
printf '%s' 'your-store-pass-key' > pass.key      # omit for stores without a pass key
chmod 644 pass.key explorer.env                   # the service runs as uid 10001; see below
```

Then, from the repository on your host:

```sh
docker compose -f .devcontainer/compose.yaml --profile explorer up -d --build explorer
```

Use `ASKAR_EXPLORER_HOME=/some/dir` to keep these files elsewhere. In the dev container the
MCP server `askar-explorer` is registered for VS Code agent mode, and the CLI environment
is preconfigured (`ASKAR_EXPLORER_AGENT_URL`, `ASKAR_EXPLORER_TOKEN_FILE`), so an agent can
also run `askar-explorer mcp` or call the HTTP API directly. To reach a database on your
laptop (an SSH tunnel or `kubectl port-forward`), use `host.docker.internal` in the URI.

To try it without a real database, create a fake store and point the service at it:

```sh
cargo run -p askar-explorer --example seed_demo -- sqlite://$HOME/.askar-explorer/store.db
echo 'ASKAR_EXPLORER_URI=sqlite:///config/store.db' > ~/.askar-explorer/explorer.env
chmod 755 ~/.askar-explorer && chmod 666 ~/.askar-explorer/store.db   # demo only
```

**Reviewing what an agent proposed.** When an agent calls `propose_change`, it reports a
proposal id and a command. You run it on your host, in the service that holds the keys:

```sh
explorer="docker compose -f .devcontainer/compose.yaml --profile explorer exec explorer askar-explorer"
$explorer changes list
$explorer changes show p-3fa9c1d07b2e       # real before and after
$explorer changes apply p-3fa9c1d07b2e --commit --confirm-backup
```

Applying needs a write connection, which you put in `explorer.env` and which exists only in
that service: `ASKAR_EXPLORER_WRITE_URI=postgres://writer:secret@db.example.com:5432/mediator`.
Keep `ASKAR_EXPLORER_URI` read-only. The dev container has neither, and it cannot reach the
proposals volume; its only route is the agent API, which can add a proposal but not apply,
reject, read or delete one.

**Limits of this boundary.**

- The files in `~/.askar-explorer` must be readable by the service's user (uid 10001), so
  on a shared machine other local users could read them. Prefer a single-user machine, or
  a Docker secret for `pass.key`.
- The token only unlocks the redacted view, so it is world-readable inside the shared
  volume by design.
- Rebuild the explorer image only from source you have reviewed: agents can edit the
  workspace, and the image is built from it.
- Anything that can run a shell **on your host** (including an agent started from a host
  terminal) is outside this boundary. Keep agents in the dev container.
- Use a read-only database role for `ASKAR_EXPLORER_URI`. The agent API never writes, but
  the role makes that a database guarantee.

## Configuration

The explorer reads `.env` from the **current working directory** if present.
For `cargo run` from the repository root, place it at the repository root.
For a command run from `tools/askar-explorer`, place it in that directory.
`.env` files are gitignored throughout this repository.

```dotenv
ASKAR_EXPLORER_URI='postgres://user:password@localhost:5432/wallet?schema=wallet_schema'
ASKAR_EXPLORER_OUT='./inspection.db'
ASKAR_EXPLORER_PASS_KEY='your-store-pass-key'
```

```sh
cargo run -p askar-explorer -- export
```

`ASKAR_EXPLORER_PASS_KEY` is optional; omit it to be prompted securely. For
scripts that already keep a pass key under another variable name, use
`--pass-key-env VARIABLE_NAME` instead. Explicit `--uri` and `--out` flags
override environment variables; existing shell variables override `.env`
values. Neither the pass key nor its variable name needs to appear in a URI.
Protect `.env` with filesystem permissions as well as `.gitignore` (for example,
`chmod 600 .env`); ignore rules do not protect files already committed to Git.

## Inspect in DBeaver

Connect DBeaver to the exported SQLite file. The `profiles`, `items`, and
`item_tags` tables contain decrypted data. `items.id` is the source Askar ID;
`items.row_id` is the editable file's local ID. Tags reference `items.row_id`
through `item_tags.item_row_id`. `items.value` is a BLOB, and
`readable_items.value_text` casts it to text for JSON/text values:

```sql
SELECT p.name AS profile, i.category, i.name, i.value_text, i.expiry
FROM readable_items AS i
JOIN profiles AS p ON p.id = i.profile_id;
```

For failed decryptions, inspect `category_error`, `name_error`, and
`value_error` in `items`, and `error` in `item_tags`. A failed profile-key
unlock stops the export and reports an incomplete output file.

## Edit and apply

**Back up the source database before a commit.** For a live SQLite store use
`sqlite3 store.db ".backup 'store.backup.db'"`; for PostgreSQL use `pg_dump`
with the appropriate connection details and a secure destination. Do not use
the plaintext export as a backup of encrypted data.

Edit the **tables**, not the `readable_items` view, in DBeaver. Examples:

```sql
-- Update an existing value and one of its tags.
UPDATE items SET value = CAST('{"fixed":true}' AS BLOB) WHERE category = 'records' AND name = 'broken';
UPDATE item_tags SET value = 'resolved' WHERE item_row_id =
  (SELECT row_id FROM items WHERE category = 'records' AND name = 'broken') AND name = 'status';

-- Delete an item and its tags. Remove tags explicitly if your SQLite client has foreign keys disabled.
DELETE FROM item_tags WHERE item_row_id = (SELECT row_id FROM items WHERE category = 'records' AND name = 'old');
DELETE FROM items WHERE category = 'records' AND name = 'old';

-- Add an ordinary item (kind defaults to 2); choose the profile from the profiles table.
INSERT INTO items (profile_id, category, name, value)
  SELECT id, 'records', 'new', CAST('{"created":true}' AS BLOB) FROM profiles WHERE name = 'main';
INSERT INTO item_tags (item_row_id, name, value, plaintext)
  SELECT row_id, 'status', 'new', 1 FROM items WHERE category = 'records' AND name = 'new';
```

For tags, `plaintext = 1` means a searchable plaintext value; `0` stores its
value encrypted. Tag names are always encrypted in Askar. Use `items.expiry`
as a UTC timestamp (`YYYY-MM-DD HH:MM:SS`), or `NULL` for no expiry. Leave
`items.row_id`, existing `items.id`, and the `original_*` and `export_meta`
tables alone; the latter are the baseline used to detect edits. New rows need
no `id`. To rename an entry, update its category/name; apply removes the old
identity and inserts the new one.

Review the proposed changes (no write to the source):

```sh
cargo run -p askar-explorer -- apply --uri 'sqlite:///path/to/store.db' --edits ./inspection.db
```

After confirming a recoverable backup, apply them through Askar's encrypted
storage API:

```sh
cargo run -p askar-explorer -- apply --uri 'sqlite:///path/to/store.db' \
  --edits ./inspection.db --commit --confirm-backup
```

As with export, the URI can come from `ASKAR_EXPLORER_URI` in `.env`; apply's
`--edits` defaults to `ASKAR_EXPLORER_OUT`. The pass key uses the same prompt,
`ASKAR_EXPLORER_PASS_KEY`, or `--pass-key-env` as export. No source write occurs
without `--commit --confirm-backup`. Apply checks that the source profiles and
key match the export and that changed existing values/tags have not changed
since export. A conflict rolls back that profile's transaction. Each profile
commits separately, so a later profile's failure cannot undo earlier profile
commits. **Re-export after a successful apply**; repeating the same export may
fail or conflict. Rows with decryption errors and expired rows cannot be
modified through this API. Apply loads the export into memory to compare it;
on very large stores, limit the export size using a separate copied store.

## Dev container

Open the repository in VS Code and choose **Dev Containers: Reopen in
Container**. The container includes the current stable Rust toolchain, Clippy,
rustfmt, Python 3, Poetry, `psql`, `pg_dump`, and `sqlite3`. A disposable PostgreSQL 16
service starts alongside it, reachable from the container as `postgres`;
`POSTGRES_URL` is preconfigured for the repository's `pg_test` tests:

```sh
cargo test -p askar-explorer
cargo test -p askar-storage --features pg_test
```

For the Python wrapper, build the native library, then install and test with
Poetry from the mounted workspace:

```sh
cargo build
cp "$CARGO_TARGET_DIR/debug/libaries_askar.so" wrappers/python/aries_askar/
cd wrappers/python
poetry install
poetry run pytest -k 'not contention'
```

The repository is mounted at `/workspace`. To inspect a Postgres service
running on your host, use `host.docker.internal` instead of `localhost` in
`ASKAR_EXPLORER_URI`. Do not put production credentials in the devcontainer
configuration. The bundled Postgres credentials are for local tests only. From
the host, its test-only service is available on `localhost:55432`.

**The output is unencrypted.** It is created with owner-only permissions on
Unix, but restrict access to its containing directory and delete the file
when finished. SQLite may create temporary sidecar files. Editing the exported
database alone does **not** change the Askar store; only `apply --commit
--confirm-backup` does.
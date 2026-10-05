use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
};

use askar_storage::{
    crypto::buffer::SecretBytes,
    entry::{EntryKind, EntryOperation, EntryTag},
    generate_raw_store_key, Backend, BackendSession, ManageBackend, PassKey, StoreKeyMethod,
};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

type SeedRow = (
    EntryKind,
    &'static str,
    &'static str,
    Vec<u8>,
    Vec<EntryTag>,
);

fn rows() -> Vec<SeedRow> {
    let person = json!({"token": "TOKEN-MARKER-1", "status": "ok", "age": 4242424242u64});
    let owner = || EntryTag::Encrypted("owner".into(), "OWNER-MARKER".into());
    vec![
        (
            EntryKind::Item,
            "people",
            "NAME-MARKER-alice",
            person.to_string().into_bytes(),
            vec![
                EntryTag::Plaintext("state".into(), "active".into()),
                owner(),
            ],
        ),
        (
            EntryKind::Item,
            "people",
            "NAME-MARKER-carol",
            person.to_string().into_bytes(),
            vec![owner()],
        ),
        (
            EntryKind::Item,
            "notes",
            "n",
            b"RAW-TEXT-MARKER plain".to_vec(),
            vec![],
        ),
        (
            EntryKind::Kms,
            "keys",
            "k",
            b"KEY-MATERIAL-MARKER".to_vec(),
            vec![],
        ),
    ]
}

async fn seed(backend: &impl Backend) {
    let mut session = backend.session(None, false).unwrap();
    for (kind, category, name, value, tags) in rows() {
        let value = SecretBytes::from(value);
        session
            .update(
                kind,
                EntryOperation::Insert,
                category,
                name,
                Some(&value),
                Some(&tags),
                None,
            )
            .await
            .unwrap();
    }
    session.close(true).await.unwrap();
}

struct Server {
    child: Child,
    base: String,
    token: String,
    token_file: std::path::PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(uri: &str, directory: &Path, envs: &[(&str, String)]) -> Server {
    let policy = directory.join("policy.toml");
    std::fs::write(
        &policy,
        "show_tags = [\"state\"]\nshow_paths = [\"status\"]\n",
    )
    .unwrap();
    let token_file = directory.join("shared").join("agent.token");
    let mut command = Command::new(env!("CARGO_BIN_EXE_askar-explorer"));
    command
        .env_remove("ASKAR_EXPLORER_URI")
        .env_remove("ASKAR_EXPLORER_PASS_KEY")
        .env_remove("ASKAR_EXPLORER_PASS_KEY_FILE")
        .env_remove("ASKAR_EXPLORER_POLICY")
        .args(["serve", "--uri", uri, "--agent-listen", "127.0.0.1:0"])
        .arg("--policy")
        .arg(&policy)
        .arg("--token-file")
        .arg(&token_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (name, value) in envs {
        command.env(name, value);
    }
    let mut child = command.spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = lines.next().expect("the server printed nothing").unwrap();
    let address = line
        .strip_prefix("Agent API listening on ")
        .unwrap_or_else(|| panic!("unexpected output: {line}"));
    let token = std::fs::read_to_string(&token_file)
        .unwrap()
        .trim()
        .to_owned();
    Server {
        child,
        base: format!("http://{address}"),
        token,
        token_file,
    }
}

impl Server {
    async fn get(&self, client: &Client, path: &str) -> (StatusCode, Value) {
        let response = client
            .get(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap();
        (
            response.status(),
            response.json().await.unwrap_or(Value::Null),
        )
    }

    async fn post(&self, client: &Client, path: &str, body: Value) -> (StatusCode, Value) {
        let response = client
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .unwrap();
        (
            response.status(),
            response.json().await.unwrap_or(Value::Null),
        )
    }
}

#[tokio::test]
async fn agent_api_is_authenticated_redacted_and_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.db");
    let backend = askar_storage::sqlite::SqliteStoreOptions::new(path.to_str().unwrap())
        .unwrap()
        .provision_backend(
            StoreKeyMethod::Unprotected,
            PassKey::empty(),
            Some("main".into()),
            false,
        )
        .await
        .unwrap();
    seed(&backend).await;
    backend.close().await.unwrap();
    let server = start(
        &format!("sqlite://{}", path.display()),
        directory.path(),
        &[],
    );
    let client = Client::new();
    let mut seen = String::new();
    let mut remember = |(status, body): (StatusCode, Value)| {
        assert!(status.is_success(), "{status}: {body}");
        seen.push_str(&body.to_string());
        body
    };

    // Authentication comes first, on every route.
    for (method, route) in [
        ("GET", "/v1/profiles"),
        ("GET", "/v1/stats"),
        ("POST", "/v1/query"),
    ] {
        let request = match method {
            "GET" => client.get(format!("{}{route}", server.base)),
            _ => client
                .post(format!("{}{route}", server.base))
                .json(&json!({"sql": "SELECT 1"})),
        };
        assert_eq!(
            request.send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let wrong = request_with_token(&client, method, &server.base, route, "not-the-token").await;
        assert_eq!(wrong, StatusCode::UNAUTHORIZED);
    }

    let profiles = remember(server.get(&client, "/v1/profiles").await);
    assert_eq!(profiles["columns"], json!(["id", "profile", "key"]));
    assert_eq!(profiles["rows"][0][1], "main");
    let stats = remember(server.get(&client, "/v1/stats").await);
    let categories: Vec<&str> = stats["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row[2].as_str().unwrap())
        .collect();
    assert!(categories.contains(&"people") && categories.contains(&"keys"));

    let described = remember(
        server
            .post(&client, "/v1/describe", json!({"category": "people"}))
            .await,
    );
    let status_row = described["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row[0] == "field" && row[1] == "status")
        .unwrap();
    assert_eq!(status_row[7], json!(["ok (2)"]), "the policy lists status");

    let queried = remember(
        server
            .post(
                &client,
                "/v1/query",
                json!({"sql": "SELECT category, count(*) AS n FROM items GROUP BY category ORDER BY category"}),
            )
            .await,
    );
    assert_eq!(queried["columns"], json!(["category", "n"]));
    assert_eq!(queried["truncated"], false);
    remember(
        server
            .post(
                &client,
                "/v1/query",
                json!({"sql": "SELECT * FROM items", "limit": 1000000}),
            )
            .await,
    );

    let listed = remember(
        server
            .post(
                &client,
                "/v1/entries",
                json!({"category": "people", "limit": 10}),
            )
            .await,
    );
    assert_eq!(listed["rows"].as_array().unwrap().len(), 2);
    let name_column = listed["columns"]
        .as_array()
        .unwrap()
        .iter()
        .position(|column| column == "name")
        .unwrap();
    assert!(listed["rows"][0][name_column]
        .as_str()
        .unwrap()
        .starts_with("p-"));
    let id = listed["rows"][0][1].as_i64().unwrap();
    let entry = remember(server.post(&client, "/v1/entry", json!({"id": id})).await);
    assert_eq!(entry["value"]["status"], "ok");
    assert_eq!(entry["value"]["token"], "<string:14>");
    remember(
        server
            .post(
                &client,
                "/v1/entries",
                json!({"plaintext_tags": ["state=active"]}),
            )
            .await,
    );

    for secret in ["MARKER", "4242424242", "alice", "carol", "RAW-TEXT"] {
        assert!(!seen.contains(secret), "{secret} leaked:\n{seen}");
    }

    // Requests cannot choose another view, add fields, or search by unlisted values.
    for (route, body) in [
        (
            "/v1/query",
            json!({"sql": "SELECT * FROM items", "view": "reveal"}),
        ),
        (
            "/v1/query",
            json!({"sql": "SELECT * FROM items", "reveal": true}),
        ),
        ("/v1/entries", json!({"reveal": true})),
        ("/v1/entry", json!({"id": id, "view": "reveal"})),
        (
            "/v1/describe",
            json!({"category": "people", "policy": "/dev/null"}),
        ),
    ] {
        let (status, body) = server.post(&client, route, body).await;
        assert!(status.is_client_error(), "{route}: {status} {body}");
        assert!(!body.to_string().contains("MARKER"));
    }
    for (route, body) in [
        ("/v1/entries", json!({"tags": ["owner=OWNER-MARKER"]})),
        (
            "/v1/entries",
            json!({"plaintext_tags": ["phone=PHONE-MARKER"]}),
        ),
        (
            "/v1/query",
            json!({"sql": "SELECT * FROM items WHERE name = 'x'"}),
        ),
        (
            "/v1/query",
            json!({"sql": "SELECT * FROM items WHERE etag = 'owner=x'"}),
        ),
        ("/v1/entries", json!({"kind": "bogus"})),
    ] {
        let (status, body) = server.post(&client, route, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{route}: {body}");
        assert!(body["error"].is_string());
    }
    for statement in [
        "DROP TABLE items",
        "CREATE TABLE t(x)",
        "ATTACH 'x' AS y",
        "SELECT 1; SELECT 2",
    ] {
        let (status, _) = server
            .post(&client, "/v1/query", json!({"sql": statement}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{statement}");
    }
    let (status, _) = server
        .post(&client, "/v1/entry", json!({"id": 99999}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Large bodies are refused, and there is nothing to write with.
    let huge = "x".repeat(100_000);
    let (status, _) = server
        .post(&client, "/v1/query", json!({"sql": huge}))
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    for route in ["/v1/profiles", "/v1/query"] {
        let response = client
            .delete(format!("{}{route}", server.base))
            .bearer_auth(&server.token)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_client_error());
    }

    // The token is a fresh random value that others can read but nobody can write.
    assert_eq!(server.token.len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&server.token_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }
}

async fn request_with_token(
    client: &Client,
    method: &str,
    base: &str,
    route: &str,
    token: &str,
) -> StatusCode {
    let url = format!("{base}{route}");
    let request = match method {
        "GET" => client.get(url),
        _ => client.post(url).json(&json!({"sql": "SELECT 1"})),
    };
    request.bearer_auth(token).send().await.unwrap().status()
}

#[tokio::test]
async fn serve_reads_the_pass_key_from_a_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("store.db");
    let pass_key = generate_raw_store_key(None).unwrap();
    let backend = askar_storage::sqlite::SqliteStoreOptions::new(path.to_str().unwrap())
        .unwrap()
        .provision_backend(
            StoreKeyMethod::RawKey,
            pass_key.as_ref(),
            Some("main".into()),
            false,
        )
        .await
        .unwrap();
    seed(&backend).await;
    backend.close().await.unwrap();
    let key_file = directory.path().join("pass.key");
    std::fs::write(&key_file, format!("{}\n", &*pass_key)).unwrap();

    let server = start(
        &format!("sqlite://{}", path.display()),
        directory.path(),
        &[(
            "ASKAR_EXPLORER_PASS_KEY_FILE",
            key_file.display().to_string(),
        )],
    );
    let client = Client::new();
    let (status, body) = server.get(&client, "/v1/profiles").await;
    assert!(status.is_success(), "{body}");
    assert_eq!(body["rows"][0][2], "ok");
    let (status, body) = server
        .post(
            &client,
            "/v1/query",
            json!({"sql": "SELECT count(*) AS n FROM items"}),
        )
        .await;
    assert!(status.is_success(), "{body}");
    assert_eq!(body["rows"][0][0], 4);
}

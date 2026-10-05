//! End to end: the real binary, the real `git` client, and a directory store
//! shared by two instances standing in for two regions.
//!
//! Set `REMOTE_TEST_S3_ENDPOINT` (plus `REMOTE_TEST_S3_ACCESS_KEY_ID` /
//! `REMOTE_TEST_S3_SECRET_ACCESS_KEY`) to run the same flow against an
//! S3-compatible store such as MinIO instead.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const ADMIN: &str = "test-operator-token";

struct Server {
    child: Child,
    url: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(store_env: &[(String, String)], cache: &Path, prefix: &str) -> Server {
    start_with(store_env, cache, prefix, &[])
}

fn start_with(
    store_env: &[(String, String)],
    cache: &Path,
    prefix: &str,
    extra: &[(&str, &str)],
) -> Server {
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_remote"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("REMOTE_LISTEN", format!("127.0.0.1:{port}"))
        .env("REMOTE_PUBLIC_URL", &url)
        .env("REMOTE_ADMIN_TOKEN", ADMIN)
        .env("REMOTE_DEFAULT_ACCOUNT", "acct-test")
        .env("REMOTE_BUCKET_PREFIX", prefix)
        .env("REMOTE_CACHE_DIR", cache)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null());
    for (k, v) in store_env {
        cmd.env(k, v);
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    #[allow(clippy::zombie_processes)] // reaped by `Server`'s Drop
    let child = cmd.spawn().expect("spawn remote");
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Server { child, url };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("remote did not start");
}

fn git(dir: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .expect("git");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let (good, text) = git(dir, args);
    assert!(good, "git {args:?} failed:\n{text}");
    text
}

async fn call(method: &str, url: &str, token: &str, body: Option<Value>) -> (u16, Value) {
    let c = reqwest::Client::new();
    let mut req = c.request(method.parse().unwrap(), url).bearer_auth(token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

fn with_creds(url: &str, token: &str) -> String {
    url.replacen("http://", &format!("http://x-access-token:{token}@"), 1)
}

fn store_env(root: &Path) -> Vec<(String, String)> {
    match std::env::var("REMOTE_TEST_S3_ENDPOINT") {
        Ok(ep) => vec![
            ("REMOTE_STORE".into(), "s3".into()),
            ("REMOTE_S3_ENDPOINT".into(), ep),
            // Exercise the AWS bucket hardening calls too.
            ("REMOTE_S3_HARDEN".into(), "1".into()),
            (
                "REMOTE_S3_ACCESS_KEY_ID".into(),
                std::env::var("REMOTE_TEST_S3_ACCESS_KEY_ID")
                    .unwrap_or_else(|_| "minioadmin".into()),
            ),
            (
                "REMOTE_S3_SECRET_ACCESS_KEY".into(),
                std::env::var("REMOTE_TEST_S3_SECRET_ACCESS_KEY")
                    .unwrap_or_else(|_| "minioadmin".into()),
            ),
        ],
        Err(_) => vec![("REMOTE_STORE".into(), format!("fs:{}", root.display()))],
    }
}

#[tokio::test]
async fn push_clone_commit_and_race_across_two_instances() {
    let tmp = tempfile::tempdir().unwrap();
    let env = store_env(&tmp.path().join("store"));
    // Unique per run so a shared MinIO starts clean.
    let prefix = format!("t{}", rand::random::<u32>());
    let a = start(&env, &tmp.path().join("cache-a"), &prefix);
    let b = start(&env, &tmp.path().join("cache-b"), &prefix);

    // Create a repo and a write token on instance A.
    let (st, repo) = call(
        "POST",
        &format!("{}/api/repos/team-a", a.url),
        ADMIN,
        Some(json!({"name": "site"})),
    )
    .await;
    assert_eq!(st, 201, "{repo}");
    let clone_url = repo["clone_url"].as_str().unwrap().to_string();
    let (st, tok) = call(
        "POST",
        &format!("{}/api/tokens", a.url),
        ADMIN,
        Some(json!({"namespace": "team-a", "repos": ["site"], "access": "write", "name": "agent"})),
    )
    .await;
    assert_eq!(st, 201, "{tok}");
    let token = tok["token"].as_str().unwrap().to_string();
    let (_, read) = call(
        "POST",
        &format!("{}/api/tokens", a.url),
        ADMIN,
        Some(json!({"namespace": "team-a", "access": "read"})),
    )
    .await;
    let read_token = read["token"].as_str().unwrap().to_string();

    // An unauthenticated clone is asked for credentials, not served.
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let (good, text) = git(&work, &["clone", &clone_url, "anon"]);
    assert!(!good, "anonymous clone must fail: {text}");

    // Push a fresh project (no prior repo) to A.
    let proj = work.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("index.html"), "<h1>hello</h1>\n").unwrap();
    ok(&proj, &["init", "-q", "-b", "main"]);
    ok(&proj, &["add", "."]);
    ok(&proj, &["commit", "-q", "-m", "first"]);
    ok(
        &proj,
        &["push", &with_creds(&clone_url, &token), "HEAD:main"],
    );

    // A read token cannot push.
    let (good, text) = git(
        &proj,
        &["push", &with_creds(&clone_url, &read_token), "HEAD:other"],
    );
    assert!(!good && text.contains("403"), "{text}");

    // Clone through B, whose cache is empty: the store is the authority.
    let b_url = clone_url.replace(&a.url, &b.url);
    ok(
        &work,
        &["clone", "-q", &with_creds(&b_url, &read_token), "via-b"],
    );
    assert_eq!(
        std::fs::read_to_string(work.join("via-b/index.html")).unwrap(),
        "<h1>hello</h1>\n"
    );

    // Two clients, both based on `first`, push to different instances; the
    // second is refused and nothing is lost.
    let c1 = work.join("c1");
    let c2 = work.join("c2");
    ok(
        &work,
        &["clone", "-q", &with_creds(&clone_url, &token), "c1"],
    );
    ok(&work, &["clone", "-q", &with_creds(&b_url, &token), "c2"]);
    std::fs::write(c1.join("a.txt"), "1").unwrap();
    ok(&c1, &["add", "."]);
    ok(&c1, &["commit", "-q", "-m", "c1"]);
    std::fs::write(c2.join("b.txt"), "2").unwrap();
    ok(&c2, &["add", "."]);
    ok(&c2, &["commit", "-q", "-m", "c2"]);
    ok(&c1, &["push", "-q", "origin", "HEAD:main"]);
    let (good, text) = git(&c2, &["push", "origin", "HEAD:main"]);
    assert!(!good, "the stale push must be refused: {text}");
    // After fetching and rebasing it goes through B.
    ok(&c2, &["pull", "-q", "--rebase", "origin", "main"]);
    ok(&c2, &["push", "-q", "origin", "HEAD:main"]);

    // A commit through the API, on B, with no git on the client.
    let (st, res) = call(
        "POST",
        &format!("{}/api/repos/team-a/site/commits", b.url),
        &token,
        Some(json!({
            "message": "agent upload",
            "files": [
                {"path": "index.html", "content": "<h1>updated</h1>\n"},
                {"path": "assets/logo.bin", "content": "AAEC", "encoding": "base64"},
                {"path": "a.txt", "delete": true}
            ]
        })),
    )
    .await;
    assert_eq!(st, 200, "{res}");
    assert_eq!(res["changed"], true);
    let commit = res["commit"].as_str().unwrap().to_string();

    // A stale base is a 409, not a silent overwrite.
    let (st, res) = call(
        "POST",
        &format!("{}/api/repos/team-a/site/commits", a.url),
        &token,
        Some(
            json!({"message": "x", "base": "0000000000000000000000000000000000000001",
                    "files": [{"path": "x", "content": "x"}]}),
        ),
    )
    .await;
    assert_eq!(st, 409, "{res}");

    // A sees B's commit.
    ok(&c1, &["pull", "-q", "origin", "main"]);
    assert_eq!(ok(&c1, &["rev-parse", "HEAD"]).trim(), commit);
    assert_eq!(
        std::fs::read_to_string(c1.join("index.html")).unwrap(),
        "<h1>updated</h1>\n"
    );
    assert_eq!(
        std::fs::read(c1.join("assets/logo.bin")).unwrap(),
        vec![0, 1, 2]
    );
    assert!(!c1.join("a.txt").exists());
    assert!(c1.join("b.txt").exists());

    // Repo info, listing, and the token wall.
    let (st, info) = call(
        "GET",
        &format!("{}/api/repos/team-a/site", a.url),
        &read_token,
        None,
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(info["refs"]["refs/heads/main"], commit);
    let (st, _) = call(
        "GET",
        &format!("{}/api/repos/team-b", a.url),
        &read_token,
        None,
    )
    .await;
    assert_eq!(st, 403);
    let (st, list) = call("GET", &format!("{}/api/repos/team-a", a.url), ADMIN, None).await;
    assert_eq!(st, 200);
    assert_eq!(list["repos"].as_array().unwrap().len(), 1);

    // Delete through A; B no longer serves it.
    let (st, _) = call(
        "DELETE",
        &format!("{}/api/repos/team-a/site", a.url),
        ADMIN,
        None,
    )
    .await;
    assert_eq!(st, 200);
    let (good, _) = git(
        &work,
        &["clone", "-q", &with_creds(&b_url, &read_token), "gone"],
    );
    assert!(!good);
}

// ---------------------------------------------------------------------------
// Web UI
// ---------------------------------------------------------------------------

/// app-lb's `/whoami` and the Heyo auth service's login and scopes, as far as
/// remote consults them. Two app-lb tokens (team-a admin, team-b view) and one
/// Heyo account (ada, admin of team-b only).
async fn upstream_stub() -> String {
    use axum::Json;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};

    fn bearer(h: &HeaderMap) -> String {
        h.get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("")
            .to_string()
    }
    let app = axum::Router::new()
        .route(
            "/whoami",
            get(|h: HeaderMap| async move {
                let (ns, scope) = match bearer(&h).as_str() {
                    "applb_1_a" => ("team-a", "admin"),
                    "applb_2_b" => ("team-b", "view"),
                    _ => return Err(StatusCode::UNAUTHORIZED),
                };
                Ok(Json(json!({"caller": "app-token", "admin_scope": scope, "fleet": false,
                    "namespace": ns, "deployments": [], "token": {"id": "t", "name": ns}})))
            }),
        )
        .route(
            "/api/auth/login",
            post(|Json(b): Json<Value>| async move {
                if b["email"] == "ada@example.com" && b["password"] == "pw" {
                    Ok(Json(json!({"success": true, "data": {"tokens": {"accessToken": "ada.jwt.token", "expiresIn": 3600}}})))
                } else if b["email"] == "google@example.com" {
                    // What the auth service answers for a Google account.
                    Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"success": false, "message": "Login failed", "code": "LOGIN_ERROR"}))))
                } else {
                    Err((StatusCode::UNAUTHORIZED, Json(json!({"success": false, "message": "Invalid credentials", "code": "INVALID_CREDENTIALS"}))))
                }
            }),
        )
        .route(
            "/api/auth/scopes",
            get(|h: HeaderMap| async move {
                if bearer(&h) != "ada.jwt.token" {
                    return Err(StatusCode::UNAUTHORIZED);
                }
                Ok(Json(json!({"success": true, "data": {
                    "subject": {"userId": "u-ada", "accountId": "acct", "email": "ada@example.com"},
                    "scopes": ["namespace:team-b:admin"]}})))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

struct Browser {
    http: reqwest::Client,
    base: String,
    cookie: Option<String>,
}

impl Browser {
    fn new(base: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            base: base.to_string(),
            cookie: None,
        }
    }

    async fn get(&self, path: &str) -> (u16, String, reqwest::header::HeaderMap) {
        let mut req = self.http.get(format!("{}{path}", self.base));
        if let Some(c) = &self.cookie {
            req = req.header("cookie", c);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        (status, resp.text().await.unwrap(), headers)
    }

    /// A form post; `same_origin` sends the `Origin` a browser would.
    async fn post(
        &mut self,
        path: &str,
        form: &[(&str, &str)],
        same_origin: bool,
    ) -> (u16, String, String) {
        let body: Vec<String> = form
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect();
        let mut req = self
            .http
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.join("&"));
        if same_origin {
            req = req.header("origin", &self.base);
        }
        if let Some(c) = &self.cookie {
            req = req.header("cookie", c);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        if let Some(set) = resp.headers().get("set-cookie") {
            let pair = set.to_str().unwrap().split(';').next().unwrap().to_string();
            self.cookie = (!pair.ends_with("=deleted")).then_some(pair);
        }
        let location = resp
            .headers()
            .get("location")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        (status, resp.text().await.unwrap(), location)
    }
}

#[tokio::test]
async fn web_ui_shows_each_session_only_what_app_lb_grants() {
    let tmp = tempfile::tempdir().unwrap();
    let env = store_env(&tmp.path().join("store"));
    let prefix = format!("w{}", rand::random::<u32>());
    let stub = upstream_stub().await;
    let srv = start_with(
        &env,
        &tmp.path().join("cache"),
        &prefix,
        &[("REMOTE_APPLB_URL", &stub), ("REMOTE_AUTH_URL", &stub)],
    );

    // The operator sets up a repo in each namespace and fills team-a/site.
    for (ns, name) in [("team-a", "site"), ("team-b", "docs")] {
        let (st, body) = call(
            "POST",
            &format!("{}/api/repos/{ns}", srv.url),
            ADMIN,
            Some(json!({"name": name, "description": format!("the {name} repo")})),
        )
        .await;
        assert_eq!(st, 201, "{body}");
    }
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(
        proj.join("README.md"),
        "# Hello site\n\nSee [the guide](docs/guide.md).\n\n<script>alert(1)</script>\n",
    )
    .unwrap();
    std::fs::write(
        proj.join("src/main.rs"),
        "fn main() {\n    println!(\"hi\");\n}\n",
    )
    .unwrap();
    ok(&proj, &["init", "-q", "-b", "main"]);
    ok(&proj, &["add", "."]);
    ok(&proj, &["commit", "-q", "-m", "first commit"]);
    ok(&proj, &["checkout", "-q", "-b", "feature/x"]);
    std::fs::write(proj.join("src/lib.rs"), "pub fn x() {}\n").unwrap();
    ok(&proj, &["add", "."]);
    ok(&proj, &["commit", "-q", "-m", "add lib on a branch"]);
    ok(&proj, &["tag", "v1"]);
    let url = with_creds(&format!("{}/team-a/site.git", srv.url), ADMIN);
    ok(&proj, &["push", "-q", &url, "main", "feature/x", "v1"]);
    let feature_head = ok(&proj, &["rev-parse", "HEAD"]).trim().to_string();

    // Signed out: every page asks for a sign-in and comes back.
    let mut a = Browser::new(&srv.url);
    let (st, _, h) = a.get("/team-a/site").await;
    assert_eq!(st, 303);
    assert_eq!(h["location"], "/-/login?next=%2Fteam-a%2Fsite");
    let (st, page, _) = a.get("/-/login").await;
    assert_eq!(st, 200);
    assert!(page.contains("name=\"password\""), "Heyo sign-in offered");

    // Login forgery is refused; a same-origin sign-in with an app-lb token works.
    let (st, _, _) = a.post("/-/login", &[("token", "applb_1_a")], false).await;
    assert_eq!(st, 403);
    let (st, _, loc) = a
        .post("/-/login", &[("token", "nope"), ("next", "/")], true)
        .await;
    assert_eq!((st, loc.as_str()), (401, ""));
    let (st, _, loc) = a
        .post(
            "/-/login",
            &[("token", "applb_1_a"), ("next", "/team-a/site")],
            true,
        )
        .await;
    assert_eq!((st, loc.as_str()), (303, "/team-a/site"));
    assert!(
        a.cookie
            .as_deref()
            .unwrap()
            .starts_with("heyo_git=applb_1_a")
    );

    // The dashboard lists team-a's repos and nothing of team-b.
    let (st, page, h) = a.get("/").await;
    assert_eq!(st, 200);
    assert_eq!(h["cache-control"], "private, no-store");
    assert!(
        page.contains("/team-a/site") && page.contains("the site repo"),
        "{page}"
    );
    assert!(!page.contains("team-b") && !page.contains("docs"), "{page}");
    for hidden in [
        "/team-b",
        "/team-b/docs",
        "/team-b/docs/commits",
        "/team-a/nope",
    ] {
        assert_eq!(a.get(hidden).await.0, 404, "{hidden}");
    }

    // The code tab: files, latest commit, and the README rendered safely.
    let (st, page, _) = a.get("/team-a/site").await;
    assert_eq!(st, 200);
    assert!(page.contains("/team-a/site/tree/main/src"), "{page}");
    assert!(page.contains("/team-a/site/blob/main/README.md"));
    assert!(
        page.contains("first commit") && page.contains("<h1>Hello site</h1>"),
        "{page}"
    );
    assert!(page.contains("&lt;script&gt;") && !page.contains("<script>alert"));
    assert!(page.contains("href=\"/team-a/site/blob/main/docs/guide.md\""));
    assert!(
        page.contains(&format!("{}/team-a/site.git", srv.url)),
        "clone URL shown"
    );

    // A branch with a slash, a file, raw, history, a commit, branches, tags.
    let (st, page, _) = a.get("/team-a/site/tree/feature/x/src").await;
    assert_eq!(st, 200);
    assert!(
        page.contains("lib.rs") && page.contains("main.rs"),
        "{page}"
    );
    let (st, page, _) = a.get("/team-a/site/blob/feature/x/src/main.rs").await;
    assert_eq!(st, 200);
    assert!(
        page.contains("id=\"L2\"") && page.contains("println!(&quot;hi&quot;);"),
        "{page}"
    );
    let (st, raw, h) = a.get("/team-a/site/raw/main/README.md").await;
    assert_eq!(st, 200);
    assert!(raw.starts_with("# Hello site"));
    assert_eq!(h["content-type"], "text/plain; charset=utf-8");
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .starts_with("sandbox")
    );
    assert_eq!(
        a.get("/team-a/site/blob/main/src").await.0,
        303,
        "a tree goes to tree/"
    );
    let (_, page, _) = a.get("/team-a/site/commits/feature/x").await;
    assert!(page.contains("add lib on a branch") && page.contains("first commit"));
    let (st, page, _) = a.get(&format!("/team-a/site/commit/{feature_head}")).await;
    assert_eq!(st, 200);
    assert!(
        page.contains("src/lib.rs") && page.contains(">1 addition<"),
        "{page}"
    );
    assert!(a.get("/team-a/site/branches").await.1.contains("feature/x"));
    assert!(a.get("/team-a/site/tags").await.1.contains("v1"));
    assert_eq!(a.get("/team-a/site/commit/0123456").await.0, 404);

    // Admin of team-a: create a repo and mint a token from the browser.
    let (st, _, _) = a.post("/team-a/-/new", &[("name", "fresh")], false).await;
    assert_eq!(st, 403, "cross-site form posts are refused");
    let (st, _, loc) = a
        .post(
            "/team-a/-/new",
            &[("name", "fresh"), ("description", "")],
            true,
        )
        .await;
    assert_eq!((st, loc.as_str()), (303, "/team-a/fresh"));
    let (_, page, _) = a.get("/team-a/fresh").await;
    assert!(
        page.contains("Quick setup"),
        "an empty repo explains how to push"
    );
    let (st, page, _) = a
        .post(
            "/team-a/-/tokens",
            &[
                ("name", "ci"),
                ("access", "write"),
                ("repos", "fresh"),
                ("ttl_days", "1"),
            ],
            true,
        )
        .await;
    assert_eq!(st, 200);
    assert!(
        page.contains("value=\"hrm_"),
        "the minted token is shown once"
    );
    assert_eq!(a.get("/team-b/-/tokens").await.0, 404);

    // Delete needs the name typed out.
    let (st, _, _) = a
        .post(
            "/team-a/fresh/settings/delete",
            &[("confirm", "fresh")],
            true,
        )
        .await;
    assert_eq!(st, 400);
    let (st, _, loc) = a
        .post(
            "/team-a/fresh/settings/delete",
            &[("confirm", "team-a/fresh")],
            true,
        )
        .await;
    assert_eq!((st, loc.as_str()), (303, "/team-a"));
    assert_eq!(a.get("/team-a/fresh").await.0, 404);

    // A Heyo account sees its own grants: team-b, not team-a.
    let mut ada = Browser::new(&srv.url);
    let (st, page, _) = ada
        .post(
            "/-/login",
            &[("email", "ada@example.com"), ("password", "wrong")],
            true,
        )
        .await;
    assert_eq!(st, 401);
    assert!(page.contains("Wrong email or password"), "{page}");
    let (st, page, _) = ada
        .post(
            "/-/login",
            &[("email", "google@example.com"), ("password", "x")],
            true,
        )
        .await;
    assert_eq!(st, 401);
    assert!(page.contains("sign in to Heyo with Google"), "{page}");
    let (st, _, _) = ada
        .post(
            "/-/login",
            &[("email", "ada@example.com"), ("password", "pw")],
            true,
        )
        .await;
    assert_eq!(st, 303);
    let (_, page, _) = ada.get("/").await;
    assert!(page.contains("ada@example.com"), "the account is named");
    assert!(
        page.contains("/team-b/docs") && !page.contains("/team-a/site"),
        "{page}"
    );
    assert_eq!(ada.get("/team-a/site").await.0, 404);
    assert_eq!(
        ada.get("/team-b/docs/settings").await.0,
        200,
        "admin of team-b"
    );

    // A view-tier app-lb token handed off from the front end: cross-site,
    // read-only, and only into a namespace it reaches.
    let mut viewer = Browser::new(&srv.url);
    let (st, _, _) = viewer
        .post(
            "/-/handoff",
            &[("token", "applb_2_b"), ("namespace", "team-a")],
            false,
        )
        .await;
    assert_eq!(st, 403);
    let (st, _, loc) = viewer
        .post(
            "/-/handoff",
            &[("token", "applb_2_b"), ("namespace", "team-b")],
            false,
        )
        .await;
    assert_eq!((st, loc.as_str()), (303, "/team-b"));
    let (_, page, _) = viewer.get("/team-b").await;
    assert!(page.contains("/team-b/docs") && !page.contains("New repository"));
    assert_eq!(viewer.get("/team-b/docs/settings").await.0, 404);
    assert_eq!(viewer.get("/team-b/-/new").await.0, 404);

    // Sign out clears the session.
    let (st, _, _) = viewer.post("/-/logout", &[], true).await;
    assert_eq!(st, 303);
    assert!(viewer.cookie.is_none());
    assert_eq!(viewer.get("/team-b").await.0, 303);
}

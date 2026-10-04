//! Golden wire fixtures — the contract between this crate and its clients.
//!
//! `heyctl` deliberately depends on nothing from app-lb: it re-declares the
//! wire types so that a client one version behind still renders what it
//! understands. The cost of that independence is that nothing catches a field
//! this crate starts emitting and the client silently ignores — an unknown field
//! and an absent one look identical to a lenient deserializer, which is exactly
//! how `DeploymentView::urls`, `PoolStatus::boot_timeout_secs` and three others
//! went missing from `heyctl/src/types.rs` without a single test failing.
//!
//! So: this module writes `testdata/wire/*.json` from the *real* response types,
//! and each client asserts it understood every key in them. Two properties make
//! that a contract rather than a copy —
//!
//! 1. the fixtures are built with struct literals, so adding a field to a
//!    response type stops this module compiling until somebody populates it, and
//! 2. every `DeploymentSpec` here is run through `validate()`, so a fixture
//!    cannot describe a deployment the server would refuse to hold.
//!
//! Regenerate with `UPDATE_GOLDEN=1 cargo test -p app-lb wire_golden`, and read
//! the diff: a changed fixture is a changed API.

use super::*;
use std::path::PathBuf;
use std::time::Duration;

fn wire_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("wire")
}

/// Compare `value` against `testdata/wire/<name>.json`, or rewrite it under
/// `UPDATE_GOLDEN`.
///
/// Pretty-printed with a trailing newline because these files are read by people
/// during review — the whole point is that a diff is legible.
fn golden(name: &str, value: &impl Serialize) {
    let path = wire_dir().join(format!("{name}.json"));
    let mut rendered = serde_json::to_string_pretty(value).expect("fixture must serialize");
    rendered.push('\n');

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(wire_dir()).expect("testdata/wire must be creatable");
        std::fs::write(&path, &rendered).expect("fixture must be writable");
        return;
    }

    let recorded = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{}: {e}\nrun `UPDATE_GOLDEN=1 cargo test -p app-lb wire_golden`", path.display())
    });

    // Object ordering is not part of the JSON wire contract and can change
    // when workspace feature unification enables serde_json's preserve_order.
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&recorded).expect("recorded fixture is JSON"),
        serde_json::from_str::<serde_json::Value>(&rendered).expect("rendered fixture is JSON"),
        "{} is stale — the wire format changed.\n\
         Every client re-declares these types, so this is an API change even if \
         no Rust caller broke.\n\
         Regenerate with `UPDATE_GOLDEN=1 cargo test -p app-lb wire_golden` and \
         update heyctl/src/types.rs and sdk/typescript/src/types.ts to match.",
        path.display()
    );
}

/// A spec with every optional field populated, for the given backend.
///
/// Three of them rather than one maximal spec, because the three backends are
/// mutually exclusive (`Backend`, `config.rs`) — a single spec carrying `vm`,
/// `upstreams` and `site` together would serialize fine and describe a
/// deployment that cannot exist.
fn vm_spec() -> DeploymentSpec {
    DeploymentSpec {
        ingress: None,
        account_id: None,
        user_id: None,
        namespace: "default".into(),
        feed: None,
        id: "sandbox".into(),
        routes: vec![
            crate::config::RouteRule {
                host: Some("sandbox.example.com".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
            },
            crate::config::RouteRule {
                host: None,
                host_suffix: Some("sb.example.com".into()),
                path_prefix: Some("/api".into()),
                strip_prefix: false,
            },
        ],
        maintenance: false,
        vm: Some(crate::config::VmSpec {
            correlated_creates: false,
            env_from: vec![],
            workspace_archive: None,
            image_download_url: None,
            image_size_bytes: None,
            image_sha256: None,
            driver: crate::config::Driver::Firecracker,
            image: Some("agent-base".into()),
            port: 8080,
            start_command: Some("/usr/local/bin/agent serve".into()),
            size_class: Some(heyo_sdk::SandboxSize::Medium),
            disk_size_gb: Some(20),
            working_directory: Some("/workspace".into()),
            env_vars: Some(
                [("RUST_LOG".to_string(), "info".to_string())]
                    .into_iter()
                    .collect(),
            ),
            setup_hooks: Some(vec!["apt-get update".into()]),
            open_ports: vec![9229],
            // One mount with every optional field set, and a resolved digest:
            // the pulled state is the one a client renders, and a fixture
            // showing the pre-pull shape would leave `digest` untested.
            mounts: vec![crate::config::MountSpec {
                path: "/data/corpus".into(),
                store: "http://127.0.0.1:8080".into(),
                artifact_ref: "corpus-2026-08".into(),
                auth: Some(crate::secrets::SecretRef {
                    namespace: None,
                    secret: "art-key".into(),
                    key: "token".into(),
                    username: None,
                }),
                strip_components: Some(1),
                read_only: true,
                digest: Some(
                    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0".into(),
                ),
            }],
            workspace: None,
            ttl_seconds: 86400,
        }),
        scaling: crate::config::ScalingPolicy {
            min_replicas: 0,
            max_replicas: 1,
            warm_pool: 0,
            target_concurrency: 1,
            scale_to_zero_after_secs: 900,
            cold_start_timeout_secs: 120,
            drain_timeout_secs: 30,
            boot_timeout_secs: 300,
            idle_action: crate::config::IdleAction::Retain,
        },
        health: crate::config::HealthCheck {
            expected_header: Some(crate::config::ExpectedHeader { name: "x-heyo-revision".into(), value: "0123456789abcdef0123456789abcdef01234567".into() }),
            path: Some("/healthz".into()),
            port: Some(8080),
            timeout_secs: 2,
        },
        upstreams: vec![],
        discovery: None,
        gateway: None,
        build: Some(crate::config::BuildSpec {
            repo: Some("https://github.com/example/agent".into()),
            store: None,
            source_ref: Some("main".into()),
            dockerfile: Some("Dockerfile".into()),
            context: Some(".".into()),
            image_name: Some("agent-base".into()),
            image_size_mb: Some(4096),
            auth: Some(crate::secrets::SecretRef {
                namespace: None,
                secret: "github".into(),
                key: "token".into(),
                username: Some("git".into()),
            }),
        }),
        artifact: None,
        site: None,
        update: None,
        auth: Some(crate::config::AuthGate {
            provider: Default::default(),
            client_id: Some("1234.apps.googleusercontent.com".into()),
            client_secret: Some(crate::secrets::SecretRef {
                namespace: None,
                secret: "google-oauth".into(),
                key: "client_secret".into(),
                username: None,
            }),
            allowed_domains: vec!["example.com".into()],
            allowed_emails: vec!["someone@other.example".into()],
            // Set here because this fixture is where a client author learns the
            // field exists; most gates leave it unset and mint nothing.
            session_scope: Some(crate::tokens::AdminScope::Admin),
            // Both spellings, because the golden is where a client author
            // learns the shape: one path genuinely open, one outside the
            // sign-in gate but still requiring a scope.
            public_paths: vec![
                crate::config::PublicPath::public("/healthz"),
                crate::config::PublicPath {
                    path: "/api/".into(),
                    scope: crate::config::PathScope::View,
                },
            ],
            base_path: "/__applb/auth".into(),
            session_ttl_secs: 43200,
            cookie_name: "applb_session".into(),
            cookie_domain: Some(".example.com".into()),
            redirect_url: Some("https://sandbox.example.com/__applb/auth/callback".into()),
            forward_identity: true,
            jwt: None,
            // This gate spells its identity out inline; the inherited shape is a
            // separate golden (`auth_provider` / `inherited_gate`). Unset here,
            // and `skip_serializing_if` keeps it out of the wire entirely, so
            // this fixture is byte-for-byte what it was before the field existed.
            provider_ref: None,
        }),
    }
}

/// A managed deployment as the *managed service* stores it: registered by a
/// heyo customer, so app-lb stamped the namespace's owning account and the
/// registering user onto it. The shape a billing-aware client must understand.
fn owned_vm_spec() -> DeploymentSpec {
    let mut s = vm_spec();
    s.id = "sandbox-owned".into();
    s.namespace = "team-a".into();
    s.account_id = Some("3f7c2a1e-9b4d-4c8e-a5f6-1d2e3f4a5b6c".into());
    s.user_id = Some("7a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d".into());
    s
}

fn site_spec() -> DeploymentSpec {
    DeploymentSpec {
        ingress: None,
        account_id: None,
        user_id: None,
        namespace: "default".into(),
        feed: None,
        id: "docs".into(),
        routes: vec![crate::config::RouteRule {
            host: Some("docs.example.com".into()),
            host_suffix: None,
            path_prefix: None,
            strip_prefix: false,
        }],
        vm: None,
        scaling: crate::config::ScalingPolicy::default(),
        maintenance: false,
        health: crate::config::HealthCheck::default(),
        upstreams: vec![],
        discovery: None,
        gateway: None,
        build: None,
        artifact: None,
        site: Some(crate::config::SiteSpec {
            root: "/srv/docs/dist".into(),
            index: "index.html".into(),
            not_found: Some("404.html".into()),
            spa: true,
            cache_control: "public, max-age=300".into(),
        }),
        update: Some(crate::config::UpdateSpec {
            working_dir: "/srv/docs".into(),
            commands: vec!["git pull --ff-only".into(), "npm run build".into()],
            env: Some(
                [("NODE_ENV".to_string(), "production".to_string())]
                    .into_iter()
                    .collect(),
            ),
            env_from: vec![crate::config::SecretEnv {
                namespace: None,
                secret: "npm".into(),
                key: "token".into(),
                env: Some("NPM_TOKEN".into()),
            }],
            auth: Some(crate::secrets::SecretRef {
                namespace: None,
                secret: "github".into(),
                key: "token".into(),
                username: Some("git".into()),
            }),
            timeout_secs: Some(600),
            verify_timeout_secs: Some(60),
        }),
        auth: None,
    }
}

fn static_spec() -> DeploymentSpec {
    DeploymentSpec {
        ingress: None,
        account_id: None,
        user_id: None,
        namespace: "default".into(),
        feed: None,
        id: "legacy".into(),
        routes: vec![crate::config::RouteRule {
            host: None,
            host_suffix: None,
            path_prefix: Some("/legacy".into()),
            strip_prefix: false,
        }],
        vm: None,
        scaling: crate::config::ScalingPolicy::default(),
        maintenance: false,
        health: crate::config::HealthCheck::default(),
        upstreams: vec!["10.0.0.4:8080".into(), "10.0.0.5:8080".into()],
        discovery: Some(crate::config::DiscoverySpec {
            service_id: "cloud".into(),
            region: None,
            source: None,
            regional: None,
        }),
        gateway: None,
        build: None,
        artifact: None,
        site: None,
        update: None,
        auth: None,
    }
}

/// A JWT-gated spec, so `JwtSpec` appears in the fixtures at all.
///
/// Its own fixture rather than a field on [`vm_spec`]: a gate accepting Google
/// and a gate accepting a JWT are different policies, and the Google one is what
/// every client has been rendering — adding a `jwt` block to it would change a
/// fixture nobody's code has a reason to re-read.
fn jwt_spec() -> DeploymentSpec {
    let mut s = vm_spec();
    s.id = "search".into();
    s.build = None;
    s.auth = Some(crate::config::AuthGate {
        // Both, because the mixed gate is the interesting one: a person opens
        // the UI in a browser, the UI's own calls carry the token it was issued.
        provider: serde_json::from_str(r#"["google","jwt"]"#).expect("providers parse"),
        client_id: Some("1234.apps.googleusercontent.com".into()),
        client_secret: Some(crate::secrets::SecretRef {
            namespace: None,
            secret: "google-oauth".into(),
            key: "client_secret".into(),
            username: None,
        }),
        allowed_domains: vec!["example.com".into()],
        allowed_emails: vec![],
        session_scope: None,
        public_paths: vec!["/healthz".into()],
        base_path: "/__applb/auth".into(),
        session_ttl_secs: 43200,
        cookie_name: "applb_session".into(),
        cookie_domain: None,
        redirect_url: None,
        forward_identity: true,
        jwt: Some(crate::config::JwtSpec {
            secret: Some(crate::secrets::SecretRef {
                namespace: None,
                secret: "heyo-auth".into(),
                key: "jwt_secret".into(),
                username: None,
            }),
            public_key: None,
            jwks_url: None,
            algorithms: vec!["HS256".into()],
            issuer: "auth-service".into(),
            audience: Some("heyo-app".into()),
            require: [
                (
                    "role".to_string(),
                    serde_json::json!(["user", "admin"]),
                ),
                ("accountId".to_string(), serde_json::json!("acct_7f3c")),
            ]
            .into_iter()
            .collect(),
            subject_claim: "userId".into(),
            email_claim: "email".into(),
            name_claim: "name".into(),
            leeway_secs: Some(30),
            cookie: Some("heyo_access_token".into()),
            login_endpoint: None,
            // A token-less browser at this gate is bounced here to sign in and
            // redirected back; the cookie above carries the token on the return.
            login_url: Some("https://auth.example.com/login".into()),
            login_redirect_param: None,
        }),
        provider_ref: None,
    });
    s
}

/// An artifact-backed spec, so `ArtifactSpec` appears in the fixtures at all.
/// Separate from [`vm_spec`] because a deployment builds its image or pulls one,
/// never both.
fn artifact_spec() -> DeploymentSpec {
    let mut s = vm_spec();
    s.id = "sandbox-pull".into();
    s.build = None;
    s.auth = None;
    s.artifact = Some(crate::config::ArtifactSpec {
        store: "http://127.0.0.1:8080".into(),
        artifact_ref: "agent-base".into(),
        auth: Some(crate::secrets::SecretRef {
            namespace: None,
            secret: "art".into(),
            key: "api_key".into(),
            username: None,
        }),
        grow_gb: Some(8),
        image_name: Some("agent-base".into()),
        strip_components: None,
    });
    s
}

/// The *site* reading of the same block: a bundle unpacked into `site.root`
/// rather than a rootfs written to `vm.image`. Separate from [`site_spec`]
/// because a site deploys one way or the other — `update` or `artifact`, never
/// both — so one fixture cannot show both halves.
fn site_artifact_spec() -> DeploymentSpec {
    let mut s = site_spec();
    s.id = "docs-pull".into();
    s.update = None;
    s.artifact = Some(crate::config::ArtifactSpec {
        store: "/srv/artifacts".into(),
        artifact_ref: "docs-live".into(),
        auth: None,
        grow_gb: None,
        image_name: None,
        strip_components: Some(1),
    });
    s
}

/// Metrics with every counter and both histograms non-zero.
///
/// Driven through `Metrics`'s real recording API rather than built literally,
/// because `HistogramSnapshot` owns its bucket bounds privately — the bucket
/// *layout* is part of the wire contract, and hand-writing it here would let the
/// fixture disagree with what the server actually emits.
fn populated_metrics() -> crate::metrics::Metrics {
    let m = crate::metrics::Metrics::new();
    for (status, ms) in [
        (200u16, 3u64),
        (200, 12),
        (204, 40),
        (301, 7),
        (404, 2),
        (500, 900),
    ] {
        m.record_request("sandbox", Some(status), Duration::from_millis(ms));
    }
    m.record_request("sandbox", None, Duration::from_millis(5));
    m.record_cold_start("sandbox", 4);
    m.record_cold_start("sandbox", 21);
    m.record_scale_up("sandbox", 2);
    m.record_scale_down("sandbox", 1);
    m.record_reaped("sandbox", 1);
    m.record_cold_start_wait("sandbox");
    m.record_cold_start_hit("sandbox");
    m.record_cold_start_timeout("sandbox");
    m.record_boot_timeout("sandbox");
    // A refused create, with the daemon's own words. Recorded in the fixture
    // rather than left at zero so `last_create_error` appears in the wire shape
    // at all — it is `skip_serializing_if = "Option::is_none"`, so a fixture
    // with no failure would silently omit the one field a client needs to
    // render the reason a pool is stuck.
    m.record_create_failure("sandbox", "api error (500): No space left on device");
    m.record_host_usage(true, 8, 23.5, 33_554_432_000, 9_663_676_416, 1_722_400_000_000);
    m
}

#[test]
fn deployment_status_is_stable() {
    for (name, spec) in [
        ("deployment-status-vm", vm_spec()),
        ("deployment-status-vm-owned", owned_vm_spec()),
        ("deployment-status-site", site_spec()),
        ("deployment-status-static", static_spec()),
        ("deployment-status-artifact", artifact_spec()),
        ("deployment-status-site-artifact", site_artifact_spec()),
        ("deployment-status-jwt", jwt_spec()),
    ] {
        spec.validate().unwrap_or_else(|e| {
            panic!("fixture {name} describes a deployment the server would reject: {e}")
        });

        let managed = spec.is_managed();
        let spec_site = spec.site.as_ref().map(|s| s.root.clone());
        let kind = if spec.is_site() {
            "site"
        } else if spec.is_static() {
            "static"
        } else {
            "vm"
        };

        golden(
            name,
            &DeploymentStatus {
                rollout_revision: "persisted-opaque-revision".into(),
                spec,
                kind,
                desired_replicas: if managed { 1 } else { 0 },
                ready: if managed { 1 } else { 0 },
                pending: if managed { 1 } else { 0 },
                total_in_flight: if managed { 3 } else { 0 },
                vms: if managed {
                    vec![VmStatus {
                        sandbox_id: "applb-sandbox-a1b2c3".into(),
                        addr: "172.16.0.4:8080".into(),
                        in_flight: 3,
                        healthy: true,
                        draining: false,
                    }]
                } else {
                    vec![]
                },
                workspace: None,
                // A fixed answer, not the fixture host's filesystem.
                site: spec_site.map(|root| crate::site::RootStatus {
                    root,
                    status: "ok",
                    index_present: Some(true),
                    hint: None,
                }),
            },
        );
    }
}

/// The auth-provider objects and the shape of a gate that inherits one, so a
/// client author learns both the reusable identity object and how a deployment
/// references it. The generated deployment-spec schema carries the `provider_ref`
/// field; this carries the *object* and a worked inherited gate.
#[test]
fn auth_provider_objects_are_stable() {
    // A Google provider: the identity half of a gate, named and namespaced.
    let google = crate::config::AuthProviderSpec {
        name: "corp-google".into(),
        namespace: "team-a".into(),
        description: Some("Workspace sign-in for team-a's apps".into()),
        created_at: 1_722_400_000,
        provider: crate::config::Providers::default(),
        client_id: Some("1234.apps.googleusercontent.com".into()),
        client_secret: Some(crate::secrets::SecretRef {
            namespace: None,
            secret: "google-oauth".into(),
            key: "client_secret".into(),
            username: None,
        }),
        allowed_domains: vec!["example.com".into()],
        allowed_emails: vec![],
        jwt: None,
        cookie_domain: Some(".example.com".into()),
    };
    google.validate().expect("the google provider fixture must be valid");
    golden("auth-provider-google", &google);

    // The Heyo auth API as a provider — what the `heyo` preset materialises from
    // a secret alone. Built through the same constructor the handler uses, so the
    // golden and the preset cannot drift.
    let heyo = crate::config::AuthProviderSpec {
        name: "heyo".into(),
        namespace: "team-a".into(),
        description: None,
        created_at: 1_722_400_000,
        provider: crate::config::Providers::one(crate::config::AuthProvider::Jwt),
        client_id: None,
        client_secret: None,
        allowed_domains: vec![],
        allowed_emails: vec![],
        jwt: Some(crate::config::JwtSpec::heyo(crate::secrets::SecretRef {
            namespace: None,
            secret: "heyo-auth".into(),
            key: "jwt_secret".into(),
            username: None,
        })),
        cookie_domain: None,
    };
    heyo.validate().expect("the heyo provider fixture must be valid");
    golden("auth-provider-heyo", &heyo);

    // A deployment whose gate inherits a provider: only the route-scoped fields
    // are its own, and `provider_ref` names the object above.
    let mut inheriting = vm_spec();
    inheriting.id = "team-a-app".into();
    inheriting.namespace = "team-a".into();
    inheriting.auth = Some(crate::config::AuthGate {
        provider_ref: Some("corp-google".into()),
        // Everything identity-related is unset: the provider supplies it.
        provider: crate::config::Providers::default(),
        client_id: None,
        client_secret: None,
        allowed_domains: vec![],
        allowed_emails: vec![],
        jwt: None,
        cookie_domain: None,
        // Route-scoped, this deployment's own.
        session_scope: None,
        public_paths: vec![crate::config::PublicPath::public("/healthz")],
        base_path: "/__applb/auth".into(),
        session_ttl_secs: 43200,
        cookie_name: "applb_session".into(),
        redirect_url: None,
        forward_identity: true,
    });
    inheriting
        .validate()
        .expect("the inheriting deployment fixture must be valid on its own");
    golden("deployment-inherited-gate", &inheriting);
}

#[test]
fn metrics_response_is_stable() {
    let m = populated_metrics();
    let spec = vm_spec();

    golden(
        "metrics-response",
        &MetricsResponse {
            generated_at: 1_722_400_000,
            uptime_secs: 86_400,
            host: m.host_snapshot(),
            fleet: FleetPool {
                deployments: 3,
                ready: 4,
                draining: 1,
                pending: 1,
                total_in_flight: 7,
            },
            global: m.global_snapshot(),
            obs: Some(crate::obs::ObsSnapshot {
                queued: 12_004,
                dropped: 3,
                shipped: 11_998,
                failed: 3,
                healthy: true,
            }),
            // Unreachable in the fixture, so the failure shape is what clients
            // are held to: this is the state in which every other number on the
            // page is stale and none of them say so.
            daemon: crate::metrics::DaemonSnapshot {
                reachable: false,
                last_error: Some(
                    "api error (0): network error calling /deployed-sandboxes: error sending \
                     request for url (http://127.0.0.1:34099/deployed-sandboxes)"
                        .into(),
                ),
            },
            security: Some(SecuritySummary {
                open: 12,
                urgent: 3,
                dropped: 0,
                clients_at_capacity: false,
                rules: 2,
                blocked: 1_412,
            }),
            deployments: vec![DeploymentView {
                id: spec.id.clone(),
                namespace: "default".into(),
                account_id: None,
                kind: "vm",
                upstreams: vec![],
                routed: true,
                hosts: vec!["sandbox.example.com".into()],
                urls: vec!["https://sandbox.example.com".into()],
                site_root: None,
                site_spa: false,
                job_kind: Some("build"),
                pool: PoolStatus {
                    desired_replicas: 1,
                    ready: 2,
                    draining: 1,
                    pending: 1,
                    total_in_flight: 3,
                    target_concurrency: 1,
                    min_replicas: 0,
                    max_replicas: 1,
                    warm_pool: 0,
                    utilization: Some(3.0),
                    cpu_percent: Some(41.25),
                    memory_bytes: Some(1_073_741_824),
                    boot_timeout_secs: 300,
                    cold_start_timeout_secs: 120,
                },
                vms: vec![VmView {
                    sandbox_id: "applb-sandbox-a1b2c3".into(),
                    addr: "172.16.0.4:8080".into(),
                    in_flight: 3,
                    healthy: true,
                    draining: false,
                    uptime_secs: 3_600,
                    cpu_percent: Some(41.25),
                    memory_bytes: Some(1_073_741_824),
                    subdomain: None,
                }],
                pending_vms: vec![PendingVmView {
                    sandbox_id: "applb-sandbox-d4e5f6".into(),
                    age_secs: 7,
                    status: Some(heyo_sdk::SandboxStatus::Provisioning),
                }],
                metrics: m.deployment_snapshot(&spec.id),
            }],
            matched: 3,
            tracked_deployments: 3,
            // One sandbox app-lb did not create, so a client learns the host
            // has tenants the pool table does not account for.
            host_sandboxes: vec![crate::metrics::HostSandboxView {
                sandbox_id: "sb-7f3a9c".into(),
                name: "sam-dev".into(),
                status: heyo_sdk::SandboxStatus::Running,
                image: "ubuntu:24.04".into(),
                size_class: Some("medium".into()),
                guest_ip: Some("172.16.0.10".into()),
                uptime_secs: 5_400,
                cpu_percent: Some(3.5),
                memory_bytes: Some(536_870_912),
                account_id: Some("acc-team-a".into()),
                created_at: Some("2024-07-31T04:26:40+00:00".into()),
            }],
        },
    );
}

/// The site variant of `DeploymentView`, which is the only place `site_root` and
/// `site_spa` are ever emitted — and both are `skip_serializing_if`, so a client
/// that only ever saw the VM fixture would never learn they exist.
#[test]
fn a_site_view_carries_its_root_and_spa_flag() {
    let m = crate::metrics::Metrics::new();
    golden(
        "deployment-view-site",
        &DeploymentView {
            id: "docs".into(),
            namespace: "default".into(),
            account_id: None,
            kind: "site",
            upstreams: vec![],
            routed: true,
            hosts: vec!["docs.example.com".into()],
            urls: vec!["https://docs.example.com".into()],
            site_root: Some("/srv/docs/dist".into()),
            site_spa: true,
            job_kind: Some("pull"),
            pool: PoolStatus {
                desired_replicas: 0,
                ready: 0,
                draining: 0,
                pending: 0,
                total_in_flight: 0,
                target_concurrency: 10,
                min_replicas: 0,
                max_replicas: 5,
                warm_pool: 0,
                utilization: None,
                cpu_percent: None,
                memory_bytes: None,
                boot_timeout_secs: 300,
                cold_start_timeout_secs: 120,
            },
            vms: vec![],
            pending_vms: vec![],
            metrics: m.deployment_snapshot("docs"),
        },
    );
}

#[test]
fn job_records_are_stable() {
    use crate::jobs::{JobKind, JobRecord, JobStatus};

    let base = |id: &str, kind: JobKind| JobRecord {
        id: id.into(),
        deployment: "sandbox".into(),
        kind,
        status: JobStatus::Succeeded,
        started_at: 1_722_400_000,
        finished_at: Some(1_722_400_123),
        operation_id: None,
        target_namespace: None,
        intent_fingerprint: None,
        config_fingerprint: None,
        source_spec_fingerprint: None,
        readiness_verified: None,
        reconciliation_required: false,
        repo: None,
        git_ref: None,
        commit: None,
        dockerfile: None,
        image: None,
        rolled_out: false,
        store: None,
        artifact_ref: None,
        digest: None,
        bytes: None,
        reused: false,
        site_root: None,
        files: None,
        mounts: vec![],
        working_dir: None,
        commands_total: None,
        commands_run: None,
        verified: None,
        error: None,
        log: vec!["cloning …".into(), "done".into()],
    };

    golden("job-build", &JobRecord {
        repo: Some("https://github.com/example/agent".into()),
        git_ref: Some("main".into()),
        commit: Some("9f3a1c2".into()),
        dockerfile: Some("Dockerfile".into()),
        image: Some("agent-base".into()),
        rolled_out: true,
        ..base("job-001", JobKind::ImageBuild)
    });

    golden("job-pull", &JobRecord {
        store: Some("http://127.0.0.1:8080".into()),
        artifact_ref: Some("agent-base".into()),
        digest: Some("sha256:0f1e2d3c".into()),
        bytes: Some(2_147_483_648),
        reused: true,
        rolled_out: true,
        ..base("job-002", JobKind::ArtifactPull)
    });

    // The other reading of `artifact-pull`, and the only fixture carrying
    // `site_root`/`files`. A client that only ever saw `job-pull` would render a
    // site's deploy history with an empty result column.
    golden("job-site-pull", &JobRecord {
        deployment: "docs".into(),
        store: Some("/srv/artifacts".into()),
        artifact_ref: Some("docs-live".into()),
        digest: Some("0f1e2d3c4b5a".into()),
        // Zero without `reused`: a local store hardlinks the blob rather than
        // copying it, so the transfer really was free.
        bytes: Some(0),
        site_root: Some("/srv/docs/dist".into()),
        files: Some(412),
        verified: Some(true),
        ..base("job-005", JobKind::ArtifactPull)
    });

    // The third reading of a pull, and the only fixture carrying `mounts`. Its
    // per-mount outcomes are where a client learns which tree a deployment is
    // actually booting with; the top-level `digest`/`store` stay empty here,
    // because one job covers several mounts and those fields cannot say which.
    golden("job-mount-pull", &JobRecord {
        rolled_out: true,
        mounts: vec![
            crate::jobs::MountOutcome {
                path: "/data/corpus".into(),
                store: "http://127.0.0.1:8080".into(),
                artifact_ref: "corpus-2026-08".into(),
                digest: Some(
                    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0".into(),
                ),
                tree: Some(
                    "/var/lib/app-lb/mounts/0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0-s1"
                        .into(),
                ),
                files: Some(1_204),
                bytes: Some(734_003_200),
                unpacked: Some(2_147_483_648),
                reused: false,
                changed: true,
            },
            // Already on this host: nothing transferred, nothing unpacked, and
            // the pool was not recycled for it.
            crate::jobs::MountOutcome {
                path: "/opt/models".into(),
                store: "/srv/artifacts".into(),
                artifact_ref: "embed-v4".into(),
                digest: Some(
                    "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809".into(),
                ),
                tree: Some(
                    "/var/lib/app-lb/mounts/1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
                        .into(),
                ),
                files: None,
                bytes: Some(0),
                unpacked: None,
                reused: true,
                changed: false,
            },
        ],
        ..base("job-006", JobKind::MountPull)
    });

    golden("job-update", &JobRecord {
        working_dir: Some("/srv/docs".into()),
        commands_total: Some(2),
        commands_run: Some(2),
        verified: Some(true),
        ..base("job-003", JobKind::HostUpdate)
    });

    // A failure, so a client sees `error` populated and `finished_at` present
    // alongside a non-`succeeded` status — the shape a `wait_for_job` helper
    // has to terminate on.
    golden("job-failed", &JobRecord {
        status: JobStatus::Failed,
        error: Some("command 2 exited 1".into()),
        working_dir: Some("/srv/docs".into()),
        commands_total: Some(2),
        commands_run: Some(1),
        verified: Some(false),
        ..base("job-004", JobKind::HostUpdate)
    });
}

/// App-tokens. `minted-token` is the one response in the whole API that carries
/// a secret, so its shape is worth pinning hard: a client that reads the wrong
/// field there stores nothing and the credential is unrecoverable.
#[test]
fn token_responses_are_stable() {
    use crate::tokens::{AdminScope, TokenSummary};

    let fleet = TokenSummary {
        id: "7f3a9c2b1e4d".into(),
        name: "ci".into(),
        admin: AdminScope::Admin,
        namespace: None,
        deployments: vec!["*".into()],
        created_at: 1_722_400_000,
        expires_at: None,
        minted_by: None,
        last_used_at: Some(1_722_403_600),
    };
    golden("token-summary", &fleet);

    // The narrow shape: an agent's own sandbox, no admin API access, expiring.
    golden(
        "token-summary-scoped",
        &TokenSummary {
            id: "a1b2c3d4e5f6".into(),
            name: "sandbox sb-7f3a9c".into(),
            admin: AdminScope::None,
            namespace: None,
            deployments: vec!["sb-7f3a9c".into()],
            created_at: 1_722_400_000,
            expires_at: Some(1_722_486_400),
            minted_by: None,
            last_used_at: None,
        },
    );

    // The namespaced shape: confined to one namespace, reaching all of it.
    // Pins the `namespace` key's spelling and its absence elsewhere — a client
    // that misreads this walls a token into the wrong rooms.
    golden(
        "token-summary-namespaced",
        &TokenSummary {
            id: "b2c3d4e5f6a1".into(),
            name: "team-a operator".into(),
            admin: AdminScope::Admin,
            namespace: Some("team-a".into()),
            deployments: vec![],
            created_at: 1_722_400_000,
            expires_at: None,
            minted_by: None,
            last_used_at: None,
        },
    );

    golden(
        "minted-token",
        &MintedToken {
            summary: fleet,
            token: "applb_7f3a9c2b1e4d_EXAMPLEONLY0000000000000000000000000000000".into(),
        },
    );
}

/// The event feed. `feed-event` pins the JSON shape `?format=json` returns —
/// the same entries the RSS carries — and `feed-index` pins `GET /feeds`.
#[test]
fn feed_responses_are_stable() {
    golden(
        "feed-index",
        &vec![crate::admin::FeedIndexEntry { namespace: "team-a".into(), events: 12 }],
    );
    golden(
        "feed-event",
        &crate::feed::FeedEvent {
            id: 7,
            ts: 1_722_400_000,
            last_ts: 1_722_400_120,
            count: 3,
            namespace: "team-a".into(),
            deployment: "web".into(),
            kind: crate::feed::FeedEventKind::Issue,
            title: "web: cold start timed out".into(),
            detail: "a request waited 120s and no VM became available".into(),
        },
    );
}

#[test]
fn the_small_responses_are_stable() {
    golden(
        "secret-summary",
        &crate::secrets::SecretSummary {
            namespace: crate::config::DEFAULT_NAMESPACE.to_string(),
            id: "github".into(),
            description: Some("PAT for private repos".into()),
            keys: vec!["token".into(), "username".into()],
            updated_at: 1_722_400_000,
            encrypted_at_rest: true,
        },
    );

    golden(
        "cert-status",
        &crate::tls::CertStatus {
            host: "sandbox.example.com".into(),
            not_after: "2026-10-29T12:00:00Z".into(),
            issuer: "R11".into(),
            needs_renewal: false,
        },
    );

    golden(
        "exec-response",
        &ExecResponse {
            sandbox_id: "applb-sandbox-a1b2c3".into(),
            exit_code: 1,
            stdout: "total 0\n".into(),
            stderr: "ls: cannot access '/nope': No such file or directory\n".into(),
            output: "total 0\nls: cannot access '/nope': No such file or directory\n".into(),
        },
    );

    golden(
        "evict-response",
        &EvictResponse {
            sandbox_id: "applb-sandbox-a1b2c3".into(),
            outcome: "draining",
        },
    );

    golden(
        "upstream-traffic-status",
        &UpstreamTrafficResponse {
            deployment_id: "stage".into(),
            upstream: "us1.example.com:443".into(),
            state: "draining",
            healthy: true,
            in_flight: 3,
            reason: Some("regional maintenance".into()),
            started_at: Some(1_722_400_000),
        },
    );

    // The one error shape clients can parse. Every *other* error app-lb produces
    // — the 401, and every axum extractor rejection — is plain text with no JSON
    // at all, which is why a client's error path cannot assume this envelope.
    golden(
        "api-error",
        &ApiError {
            error: "no deployment \"demo\"".into(),
        },
    );
}

/// `GET /security`, with one alert of each shape a client has to render: a
/// signature hit against a deployment, and a control-plane finding that names
/// none.
///
/// The `ecs` block is the point of normalizing through u-siem at all — the field
/// *names* in this fixture are the crate's `field_dictionary` constants, so a
/// version bump that renames one shows up as a diff here. There is deliberately
/// no `url.query` key, and there never can be: no parser sets one.
#[test]
fn security_response_is_stable() {
    use crate::siem::{Alert, Severity, SeverityTotals, SiemSnapshot};

    golden(
        "security-response",
        &SecurityResponse {
            generated_at: 1_722_400_000,
            enabled: true,
            window_secs: 60,
            alerts: vec![
                Alert {
                    id: 41,
                    ts: 1_722_399_940_000,
                    last_ts: 1_722_399_998_000,
                    rule: "traffic.scanner",
                    severity: Severity::Medium,
                    title: "203.0.113.9 is probing for unserved paths".into(),
                    client: Some("203.0.113.9".into()),
                    deployment: Some("demo".into()),
                    path: Some("/wp-login.php".into()),
                    technique: Some("T1595"),
                    count: 214,
                    ecs: Some(serde_json::json!({
                        "event.action": "http-request",
                        "event.category": "web",
                        "event.outcome": "failure",
                        "http.request.method": "GET",
                        "http.response.status_code": 404,
                        "observer.name": "app-lb",
                        "source.ip": "203.0.113.9",
                        "url.domain": "demo.example.com",
                        "url.extension": "php",
                        "url.path": "/wp-login.php",
                        "tags": ["access", "external"],
                    })),
                }
                .into(),
                Alert {
                    id: 42,
                    ts: 1_722_399_980_000,
                    last_ts: 1_722_399_999_000,
                    rule: "auth.brute-force",
                    severity: Severity::High,
                    title: "198.51.100.7 is failing authentication repeatedly".into(),
                    client: Some("198.51.100.7".into()),
                    // Admin-plane: no deployment of its own, so a
                    // deployment-scoped token must not be shown this row.
                    deployment: None,
                    path: Some("/metrics".into()),
                    technique: Some("T1110"),
                    count: 9,
                    ecs: Some(serde_json::json!({
                        "event.action": "admin-rejected",
                        "event.category": "authentication",
                        "event.outcome": "failure",
                        "http.request.authorization.scheme": "basic",
                        "observer.name": "app-lb",
                        "source.ip": "198.51.100.7",
                        "url.path": "/metrics",
                        "tags": ["auth-failure", "external"],
                    })),
                }
                .into(),
            ],
            totals: SeverityTotals {
                info: 0,
                low: 0,
                medium: 11,
                high: 3,
                critical: 0,
            },
            // One rule of each shape a client renders: a timed block created
            // from an alert, and a permanent exemption.
            rules: vec![
                crate::guard::RuleView {
                    id: "5f295e1a86f2".into(),
                    action: crate::guard::RuleAction::Block,
                    match_: crate::guard::MatchSpec {
                        client: Some("203.0.113.9".into()),
                        ..Default::default()
                    },
                    summary: "from 203.0.113.9".into(),
                    note: Some("traffic.scanner alert #41".into()),
                    created_at: 1_722_399_400,
                    expires_at: Some(1_722_485_800),
                    hits: 1_412,
                    last_hit: Some(1_722_399_990),
                    enforcing: true,
                    // A rule that is doing something, and one that is not — the
                    // distinction the console's per-rule chart exists to draw.
                    hits_recent: vec![0, 0, 4, 61, 128, 44, 9, 0],
                },
                crate::guard::RuleView {
                    id: "b1d0c4470c3e".into(),
                    action: crate::guard::RuleAction::Allow,
                    match_: crate::guard::MatchSpec {
                        client: Some("10.0.0.0/8".into()),
                        ..Default::default()
                    },
                    summary: "from 10.0.0.0/8".into(),
                    note: Some("internal monitoring".into()),
                    created_at: 1_722_300_000,
                    expires_at: None,
                    hits: 0,
                    last_hit: None,
                    enforcing: true,
                    // Deliberately all-zero: an exemption that has never fired
                    // renders as an empty chart, and a client that treats a flat
                    // series as "no data" rather than "no hits" would be wrong.
                    hits_recent: vec![0, 0, 0, 0, 0, 0, 0, 0],
                },
            ],
            guard: crate::guard::GuardStats {
                rules: 2,
                blocked: 1_412,
                exempted: 87,
                enforcing: true,
                blocked_recent: vec![0, 0, 4, 61, 128, 44, 9, 0],
                exempted_recent: vec![0, 1, 1, 0, 2, 1, 1, 0],
                hits_bucket_secs: 60,
                hits_window_secs: 3_600,
            },
            stats: Some(SiemSnapshot {
                observed: 918_273,
                dropped: 0,
                analyzed: 918_273,
                raised: 14,
                suppressed: 4_118,
                tracked_clients: 118,
                clients_at_capacity: false,
            }),
        },
    );
}

/// A workflow object with every optional field populated.
///
/// Maximal on purpose: the fixture's job is to catch a field that stops being
/// serialized, and an absent field cannot go missing.
fn workflow_spec() -> crate::config::WorkflowSpec {
    crate::config::WorkflowSpec {
        id: "build".into(),
        repo: "https://github.com/Heyo-Computer/app.git".into(),
        git_ref: "main".into(),
        path: ".ci/workflows/*.yml".into(),
        network: "prod-runners".into(),
        auth: Some(crate::secrets::SecretRef {
            namespace: None,
            secret: "github".into(),
            key: "token".into(),
            username: None,
        }),
        secrets_prefix: Some("ci/app".into()),
        enabled: true,
    }
}

#[test]
fn workflow_spec_is_stable() {
    let spec = workflow_spec();
    spec.validate()
        .unwrap_or_else(|e| panic!("the fixture describes a workflow the server would reject: {e}"));
    golden("workflow", &spec);

    // The list shape the `ci` orchestrator polls. Enveloped rather than a bare
    // array so the response can grow a cursor without becoming a breaking
    // change.
    golden(
        "workflow-list",
        &serde_json::json!({ "workflows": [workflow_spec()] }),
    );
}

/// `GET /disks` — the inventory `heyctl get disks` renders.
///
/// Built with struct literals like every fixture here, so a field added to
/// `DiskInfo` or `Totals` stops this module compiling until somebody decides
/// whether the client should show it. That matters more for this response than
/// most: the disk console was the only reader for a long time, and a column it
/// quietly stopped rendering is a gigabyte nobody accounts for.
///
/// One row per state that reads differently, because the states are the whole
/// point of the listing: a running VM's disk (never reclaimed), an orphan with
/// no daemon record (pure residue), and one an operator pinned with `retain`.
#[test]
fn disk_inventory_is_stable() {
    use crate::disks::{
        DEFAULT_ORPHAN_TTL_SECS, DiskInfo, DiskPart, DiskState, Inventory, PartKind, Totals,
    };

    let running = DiskInfo {
        sandbox_id: "sb-1a2b3c4d".into(),
        name: Some("applb-web-00000000002a".into()),
        deployment: Some("web".into()),
        state: DiskState::Running,
        claimed: true,
        retain: false,
        note: None,
        bytes: 1_073_741_824,
        // Sparse: the guest sees 8 GiB where the host has lost 1 GiB. The two
        // columns exist because these routinely disagree by this much.
        apparent_bytes: 8_589_934_592,
        modified_at: 1_760_000_000,
        expires_at: None,
        held_by: Some("in use by a running sandbox"),
        archived: None,
        parts: vec![
            DiskPart {
                kind: PartKind::Data,
                path: "run/sb-1a2b3c4d/data.ext4".into(),
                bytes: 1_073_741_824,
                apparent_bytes: 8_589_934_592,
                modified_at: 1_760_000_000,
            },
            DiskPart {
                kind: PartKind::Rootfs,
                path: "run/sb-1a2b3c4d/rootfs.ext4".into(),
                bytes: 1_178_599_424,
                apparent_bytes: 1_178_599_424,
                modified_at: 1_760_000_000,
            },
        ],
        roots: vec!["run/sb-1a2b3c4d".into()],
    };

    let orphan = DiskInfo {
        sandbox_id: "sb-99887766".into(),
        name: None,
        deployment: None,
        state: DiskState::Orphan,
        claimed: false,
        retain: false,
        note: None,
        bytes: 2_147_483_648,
        apparent_bytes: 2_147_483_648,
        modified_at: 1_759_000_000,
        expires_at: Some(1_759_604_800),
        held_by: None,
        archived: None,
        parts: vec![DiskPart {
            kind: PartKind::Data,
            path: "run/sb-99887766/data.ext4".into(),
            bytes: 2_147_483_648,
            apparent_bytes: 2_147_483_648,
            modified_at: 1_759_000_000,
        }],
        roots: vec!["run/sb-99887766".into()],
    };

    let pinned = DiskInfo {
        sandbox_id: "sb-deadbeef".into(),
        name: Some("applb-api-000000000007".into()),
        deployment: Some("api".into()),
        state: DiskState::Stopped,
        claimed: false,
        retain: true,
        note: Some("keeping for the incident postmortem".into()),
        bytes: 536_870_912,
        apparent_bytes: 4_294_967_296,
        modified_at: 1_758_000_000,
        expires_at: None,
        held_by: Some("retained by an operator"),
        archived: None,
        parts: vec![DiskPart {
            kind: PartKind::Data,
            path: "run/sb-deadbeef/data.ext4".into(),
            bytes: 536_870_912,
            apparent_bytes: 4_294_967_296,
            modified_at: 1_758_000_000,
        }],
        roots: vec!["run/sb-deadbeef".into()],
    };

    golden(
        "disks",
        &Inventory {
            complete: true,
            incomplete_reason: None,
            data_dir: "/var/lib/heyo".into(),
            tmp_dir: "/tmp".into(),
            ttl_secs: 604_800,
            sweep_secs: 3600,
            archive_enabled: false,
            archive_on_expire: false,
            archive_target: None,
            free_bytes: Some(12_884_901_888),
            filesystem_bytes: Some(536_870_912_000),
            orphan_ttl_secs: DEFAULT_ORPHAN_TTL_SECS,
            totals: Totals {
                disks: 3,
                bytes: 3_758_096_384,
                apparent_bytes: 15_032_385_536,
                running: 1,
                stopped: 1,
                orphan: 1,
                retained: 1,
                expiring_now: 1,
                reclaimable_bytes: 2_147_483_648,
            },
            disks: vec![running, orphan, pinned],
            archives: vec![],
        },
    );
}

/// A minimal object must round-trip through its defaults, or `heyctl create
/// workflow` would have to send every field.
#[test]
fn a_minimal_workflow_fills_its_defaults() {
    let minimal: crate::config::WorkflowSpec = serde_json::from_str(
        r#"{"id":"build","repo":"https://example.com/a.git","network":"prod"}"#,
    )
    .expect("a minimal object parses");
    assert_eq!(minimal.git_ref, "main");
    assert_eq!(minimal.path, ".ci/workflows/*.yml");
    assert!(minimal.enabled);
    golden("workflow-minimal", &minimal);
}

/// `GET /api/plugins` — the plugin list the console and `heyctl plugins` read.
#[test]
fn plugin_list_is_stable() {
    use crate::plugins::{PluginMeta, PluginView};
    let enabled = PluginView {
        meta: PluginMeta {
            id: "example",
            name: "Example",
            description: "A plugin that is switched on and failing.",
            config_schema: serde_json::json!({
                "type": "object",
                "properties": {"url": {"type": "string"}},
            }),
        },
        enabled: true,
        config: serde_json::json!({"url": "http://127.0.0.1:34199"}),
        updated_at: 1_760_000_000,
        last_error: Some("connection refused".into()),
        status: serde_json::json!({"state": "retrying"}),
    };
    let disabled = PluginView {
        meta: PluginMeta {
            id: "idle",
            name: "Idle",
            description: "A plugin nobody switched on.",
            config_schema: serde_json::json!({"type": "object"}),
        },
        enabled: false,
        config: serde_json::Value::Null,
        updated_at: 0,
        last_error: None,
        status: serde_json::json!({}),
    };
    golden("plugins", &vec![enabled, disabled]);
}

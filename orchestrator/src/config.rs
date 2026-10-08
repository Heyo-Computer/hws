use anyhow::{Context, Result};
use config::{Config as ConfigBuilder, Environment, File};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NatsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nats_url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_port: u16,
    pub database_url: String,
    #[serde(default = "default_db_max_connections")]
    pub db_max_connections: u32,
    #[serde(default = "default_db_min_connections")]
    pub db_min_connections: u32,
    #[serde(default = "default_db_connect_timeout_seconds")]
    pub db_connect_timeout_seconds: u64,
    #[serde(default = "default_db_acquire_timeout_seconds")]
    pub db_acquire_timeout_seconds: u64,
    #[serde(default = "default_db_idle_timeout_seconds")]
    pub db_idle_timeout_seconds: u64,
    #[serde(default = "default_db_max_lifetime_seconds")]
    pub db_max_lifetime_seconds: u64,
    pub agent_provider: String,
    pub agent_model: String,
    /// Optional provider + model overrides per workflow purpose. When unset,
    /// `agent_provider` / `agent_model` are used. Wired to env vars
    /// `ORCHESTRATOR_AGENT_{PROVIDER,MODEL}_{DISCOVERY,PLANNING,REVIEW,PATCH}`.
    /// The provider and model are overridden together — if the provider field
    /// is set, the corresponding model field must also be set.
    #[serde(default)]
    pub agent_provider_discovery: Option<String>,
    #[serde(default)]
    pub agent_model_discovery: Option<String>,
    #[serde(default)]
    pub agent_provider_planning: Option<String>,
    #[serde(default)]
    pub agent_model_planning: Option<String>,
    #[serde(default)]
    pub agent_provider_review: Option<String>,
    #[serde(default)]
    pub agent_model_review: Option<String>,
    #[serde(default)]
    pub agent_provider_patch: Option<String>,
    #[serde(default)]
    pub agent_model_patch: Option<String>,
    pub agent_api_key: String,
    pub agent_timeout_seconds: u64,
    pub agent_max_iterations: usize,
    pub jwt_secret: String,
    pub cloud_internal_url: String,
    #[serde(default)]
    pub heyosecret_url: String,
    #[serde(default)]
    pub heyosecret_internal_api_key: String,
    pub internal_api_key: String,

    /// Target backend OS — `"linux"` | `"darwin"` | `"windows"`. The orchestrator
    /// can run on any platform and ship plans to a backend on a different one;
    /// driver selection must therefore be a function of the *backend's* OS,
    /// not of the orchestrator's. Defaults to the orchestrator's own OS so
    /// local single-host development works without configuration, but should
    /// be overridden in production / cross-host setups via env var or
    /// `/capabilities` lookup.
    #[serde(default = "default_target_os")]
    pub target_os: String,
    /// Drivers the backend supports for sandbox runtime. First entry is used
    /// as the default when the operator picks "Auto".
    #[serde(default = "default_target_supported_drivers")]
    pub target_supported_drivers: Vec<String>,
    /// Drivers the backend supports for archive-style overlays (e.g. libvirt
    /// disk images, apple_container/apple_virt rootfs).
    #[serde(default = "default_target_archive_supported_drivers")]
    pub target_archive_supported_drivers: Vec<String>,

    /// Optional URL of the mvm-ctrl backend (e.g. `http://127.0.0.1:3334`).
    /// When set, the orchestrator fetches `GET /capabilities` at startup and
    /// uses the returned values, overriding `target_os` / `target_*_drivers`.
    /// When unset, the static Config values are used as-is.
    #[serde(default)]
    pub backend_api_url: String,

    /// Comma-separated base domains whose single-label subdomains identify
    /// backend proxy routes, for example `stage.example.com,example.com`.
    #[serde(default)]
    pub proxy_base_domains: String,

    /// Directory watched by the system Traefik file provider for Heyo-managed
    /// service routes. When set, service deployment cutovers write one
    /// `heyo-service-<service>.yml` file here instead of editing the host's
    /// static Traefik config.
    #[serde(default)]
    pub traefik_dynamic_config_dir: String,

    /// Durable state directory for blue/green service deployments. Each service
    /// gets a JSON state file with the active deployment id and retained
    /// previous deployment id.
    #[serde(default = "default_service_state_dir")]
    pub service_state_dir: String,

    /// Comma-separated service ids whose ingress is owned by app-lb discovery
    /// rather than a direct Traefik route to one deployment candidate.
    #[serde(default)]
    pub discovery_routed_services: String,

    /// All ingress app-lb instances for each discovery service. Regional
    /// rollouts require an observer in every target region and query them all.
    #[serde(default)]
    pub discovery_observers: Vec<DiscoveryObserver>,

    /// Trusted retained-workspace runtimes for adopted applications.
    #[serde(default)]
    pub external_service_bindings: Vec<ExternalServiceBinding>,

    /// Continuous healthy observation required between regional activations.
    #[serde(default = "default_regional_application_bake_seconds")]
    pub regional_application_bake_seconds: u32,

    #[serde(default)]
    pub nats: NatsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryObserver {
    pub service_id: String,
    pub region: String,
    /// Explicit hierarchical gateway identity; required for regional-v1 reports.
    #[serde(default)]
    pub gateway_id: Option<String>,
    pub deployment_id: String,
    pub base_url: String,
    /// Opt in to host-managed ingress. Origin used to probe this particular
    /// ingress, with the service route's Host header (not a global LB URL).
    #[serde(default)]
    pub ingress_url: Option<String>,
    /// Existing app-lb secret ID, in the route's default namespace, with a
    /// `token` key for this discovery authority. The value stays in app-lb.
    #[serde(default)]
    pub discovery_token_secret: Option<String>,
    /// Existing namespace-local app-lb peer-role secret ID for cold regional
    /// enrollment. This is a reference, not a credential value.
    #[serde(default)]
    pub regional_peer_token_secret: Option<String>,
    /// Exact authoritative service discovery URL, identical at every ingress.
    #[serde(default)]
    pub discovery_url: Option<String>,
    /// HeyoSecret path containing an app-lb admin bearer. Never persisted in
    /// rollout requests or returned by status APIs.
    pub token_secret_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalServiceBinding {
    pub service_id: String,
    pub authority: String,
    pub region: String,
    pub namespace: String,
    pub deployment_id: String,
    /// HeyoSecret credential scoped to this application's lifecycle exchange.
    #[serde(default)]
    pub lifecycle_token_secret_path: String,
    pub health_origin: String,
    pub token_secret_path: String,
}

impl Config {
    pub fn target_default_driver(&self) -> &str {
        self.target_supported_drivers
            .first()
            .map(String::as_str)
            .unwrap_or("firecracker_containerd")
    }

    pub fn supports_orchestration_deploy_driver(&self, driver: &str) -> bool {
        self.target_supported_drivers.iter().any(|d| d == driver)
    }

    pub fn supports_archive_deploy_driver(&self, driver: &str) -> bool {
        self.target_archive_supported_drivers
            .iter()
            .any(|d| d == driver)
    }

    pub fn supports_repo_archive_overlay(&self, driver: &str) -> bool {
        self.supports_archive_deploy_driver(driver)
            || matches!(driver, "firecracker" | "firecracker_containerd")
    }

    pub fn service_uses_discovery_routing(&self, service_id: &str) -> bool {
        self.discovery_routed_services
            .split(',')
            .any(|configured| configured.trim() == service_id)
    }
}

fn default_target_os() -> String {
    std::env::consts::OS.to_string()
}

fn default_target_supported_drivers() -> Vec<String> {
    match std::env::consts::OS {
        "macos" => vec!["apple_container".to_string(), "apple_virt".to_string()],
        _ => vec![
            "firecracker_containerd".to_string(),
            "firecracker".to_string(),
            "libvirt".to_string(),
        ],
    }
}

fn default_target_archive_supported_drivers() -> Vec<String> {
    match std::env::consts::OS {
        "macos" => vec!["apple_container".to_string(), "apple_virt".to_string()],
        _ => vec!["libvirt".to_string()],
    }
}

/// Map a step key to a purpose string. Used to pick the right per-phase
/// model override (see `Config::agent_model_for`).
pub fn purpose_from_step_key(step_key: &str) -> &'static str {
    match step_key {
        "discover_domain_model" => "discovery",
        "draft_patch_set" => "patch",
        key if key.starts_with("draft_") || key.starts_with("revise_") => "planning",
        key if key.starts_with("review_") => "review",
        _ => "default",
    }
}

impl Config {
    /// Return `(provider, model)` for a given purpose. Per-phase overrides
    /// apply only when BOTH the provider and model fields for that phase are
    /// set — a half-configured phase falls back to the global pair so we
    /// don't accidentally send a Mistral model to Anthropic's API.
    pub fn agent_for(&self, purpose: &str) -> (&str, &str) {
        let (override_provider, override_model) = match purpose {
            "discovery" => (
                self.agent_provider_discovery.as_deref(),
                self.agent_model_discovery.as_deref(),
            ),
            "planning" => (
                self.agent_provider_planning.as_deref(),
                self.agent_model_planning.as_deref(),
            ),
            "review" => (
                self.agent_provider_review.as_deref(),
                self.agent_model_review.as_deref(),
            ),
            "patch" => (
                self.agent_provider_patch.as_deref(),
                self.agent_model_patch.as_deref(),
            ),
            _ => (None, None),
        };
        match (
            override_provider.filter(|v| !v.trim().is_empty()),
            override_model.filter(|v| !v.trim().is_empty()),
        ) {
            (Some(p), Some(m)) => (p, m),
            _ => (&self.agent_provider, &self.agent_model),
        }
    }

    /// Return the model to use for a given purpose. Kept for callers that
    /// only need the model name and are OK with the existing global provider.
    pub fn agent_model_for(&self, purpose: &str) -> &str {
        self.agent_for(purpose).1
    }
}

fn default_cloud_internal_url() -> String {
    "http://127.0.0.1:4445".to_string()
}

fn default_db_max_connections() -> u32 {
    // Conservative per-process cap. Postgres `max_connections` is shared
    // across every replica of this service plus auth/cloud, so a high
    // per-process pool exhausts the server quickly. Raise via
    // `ORCHESTRATOR_DB_MAX_CONNECTIONS` only when Postgres has the capacity.
    20
}

fn default_db_min_connections() -> u32 {
    // Keep few idle connections warm per process; the pool grows on demand up
    // to `db_max_connections`. Idle connections are held by every replica.
    2
}

fn default_db_connect_timeout_seconds() -> u64 {
    8
}

fn default_db_acquire_timeout_seconds() -> u64 {
    30
}

fn default_db_idle_timeout_seconds() -> u64 {
    600
}

fn default_db_max_lifetime_seconds() -> u64 {
    1800
}

fn default_agent_provider() -> String {
    "anthropic".to_string()
}

fn default_agent_model() -> String {
    // Heavy default: Opus 4.7 for planning/review/patch (Amp-equivalent
    // workloads). Discovery runs a separate cheap provider via the phase
    // override below, so we don't pay Opus rates for repo scans.
    "claude-opus-4-7".to_string()
}

fn default_agent_provider_discovery() -> Option<String> {
    Some("mistral".to_string())
}

fn default_agent_model_discovery() -> Option<String> {
    // Use Mistral's flagship for discovery — it's the cheap provider for
    // repo-scan work but we still pick its best model so we don't pay a
    // quality tax on the summary that downstream phases depend on.
    Some("mistral-large-latest".to_string())
}

fn default_agent_timeout_seconds() -> u64 {
    900
}

fn default_agent_max_iterations() -> usize {
    15
}

fn default_nats_url() -> String {
    "nats://127.0.0.1:4222".to_string()
}

fn default_service_state_dir() -> String {
    dirs::home_dir()
        .map(|home| home.join(".heyo/orchestrator/services"))
        .unwrap_or_else(|| std::path::PathBuf::from(".heyo/orchestrator/services"))
        .to_string_lossy()
        .to_string()
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::get_config_path();

        let mut config_builder = ConfigBuilder::builder();
        config_builder = config_builder
            .set_default("server_port", 4446)?
            .set_default("database_url", "")?
            .set_default("db_max_connections", default_db_max_connections() as i64)?
            .set_default("db_min_connections", default_db_min_connections() as i64)?
            .set_default(
                "db_connect_timeout_seconds",
                default_db_connect_timeout_seconds() as i64,
            )?
            .set_default(
                "db_acquire_timeout_seconds",
                default_db_acquire_timeout_seconds() as i64,
            )?
            .set_default(
                "db_idle_timeout_seconds",
                default_db_idle_timeout_seconds() as i64,
            )?
            .set_default(
                "db_max_lifetime_seconds",
                default_db_max_lifetime_seconds() as i64,
            )?
            .set_default("agent_provider", default_agent_provider())?
            .set_default("agent_model", default_agent_model())?
            .set_default(
                "agent_provider_discovery",
                default_agent_provider_discovery(),
            )?
            .set_default("agent_model_discovery", default_agent_model_discovery())?
            .set_default("agent_api_key", "")?
            .set_default("agent_timeout_seconds", default_agent_timeout_seconds())?
            .set_default(
                "agent_max_iterations",
                default_agent_max_iterations() as i64,
            )?
            .set_default("jwt_secret", "")?
            .set_default("cloud_internal_url", default_cloud_internal_url())?
            .set_default("heyosecret_url", "")?
            .set_default("heyosecret_internal_api_key", "")?
            .set_default("internal_api_key", "")?
            .set_default("target_os", default_target_os())?
            .set_default(
                "target_supported_drivers",
                default_target_supported_drivers(),
            )?
            .set_default(
                "target_archive_supported_drivers",
                default_target_archive_supported_drivers(),
            )?
            .set_default("backend_api_url", "")?
            .set_default("proxy_base_domains", "")?
            .set_default("traefik_dynamic_config_dir", "")?
            .set_default("service_state_dir", default_service_state_dir())?
            .set_default("discovery_routed_services", "")?
            .set_default("regional_application_bake_seconds", default_regional_application_bake_seconds() as i64)?
            .set_default("nats.enabled", false)?
            .set_default("nats.url", default_nats_url())?;

        if let Some(path) = &config_path {
            if path.exists() {
                eprintln!("Loading orchestrator config from: {}", path.display());
                config_builder = config_builder.add_source(File::from(path.as_path()));
            }
        }

        config_builder = config_builder.add_source(
            Environment::with_prefix("ORCHESTRATOR")
                .separator("_")
                .try_parsing(true),
        );

        let config = config_builder.build()?;
        let observers = Self::load_discovery_observers(&config,
            env::var("ORCHESTRATOR_DISCOVERY_OBSERVERS_JSON").ok().as_deref())?;
        let external_bindings = Self::load_external_service_bindings(&config,
            env::var("ORCHESTRATOR_EXTERNAL_SERVICE_BINDINGS_JSON").ok().as_deref())?;
        let mut orchestrator_config: Config = config.try_deserialize()?;
        orchestrator_config.discovery_observers = observers;
        orchestrator_config.external_service_bindings = external_bindings;

        if let Ok(server_port) = env::var("ORCHESTRATOR_SERVER_PORT") {
            if !server_port.is_empty() {
                orchestrator_config.server_port = server_port.parse()?;
            }
        }
        if orchestrator_config.database_url.is_empty() {
            orchestrator_config.database_url = env::var("DATABASE_URL").unwrap_or_default();
        }
        if orchestrator_config.jwt_secret.is_empty() {
            orchestrator_config.jwt_secret = env::var("JWT_SECRET").unwrap_or_default();
        }
        if orchestrator_config.internal_api_key.is_empty() {
            orchestrator_config.internal_api_key = env::var("CLOUD_INTERNAL_API_KEY")
                .or_else(|_| env::var("INTERNAL_API_KEY"))
                .unwrap_or_default();
        }
        if orchestrator_config.heyosecret_url.is_empty() {
            orchestrator_config.heyosecret_url = env::var("ORCHESTRATOR_HEYOSECRET_URL")
                .or_else(|_| env::var("HEYOSECRET_URL"))
                .unwrap_or_default();
        }
        if orchestrator_config.heyosecret_internal_api_key.is_empty() {
            orchestrator_config.heyosecret_internal_api_key =
                env::var("ORCHESTRATOR_HEYOSECRET_INTERNAL_API_KEY")
                    .or_else(|_| env::var("HEYOSECRET_INTERNAL_API_KEY"))
                    .unwrap_or_default();
        }
        if orchestrator_config.agent_api_key.is_empty() {
            orchestrator_config.agent_api_key =
                env::var("ORCHESTRATOR_AGENT_API_KEY").unwrap_or_default();
        }
        if orchestrator_config.backend_api_url.is_empty() {
            orchestrator_config.backend_api_url = env::var("ORCHESTRATOR_BACKEND_API_URL")
                .or_else(|_| env::var("BACKEND_API_URL"))
                .unwrap_or_default();
        }
        if orchestrator_config.proxy_base_domains.is_empty() {
            orchestrator_config.proxy_base_domains =
                env::var("ORCHESTRATOR_PROXY_BASE_DOMAINS").unwrap_or_default();
        }
        if orchestrator_config.traefik_dynamic_config_dir.is_empty() {
            orchestrator_config.traefik_dynamic_config_dir =
                env::var("ORCHESTRATOR_TRAEFIK_DYNAMIC_CONFIG_DIR").unwrap_or_default();
        }
        if orchestrator_config.discovery_routed_services.is_empty() {
            orchestrator_config.discovery_routed_services =
                env::var("ORCHESTRATOR_DISCOVERY_ROUTED_SERVICES").unwrap_or_default();
        }
        if let Ok(service_state_dir) = env::var("ORCHESTRATOR_SERVICE_STATE_DIR") {
            if !service_state_dir.is_empty()
                && orchestrator_config.service_state_dir == default_service_state_dir()
            {
                orchestrator_config.service_state_dir = service_state_dir;
            }
        }
        if let Ok(url) = env::var("CLOUD_INTERNAL_URL") {
            if !url.is_empty() {
                orchestrator_config.cloud_internal_url = url;
            }
        }
        if let Ok(url) = env::var("ORCHESTRATOR_NATS_URL")
            .or_else(|_| env::var("CLOUD_NATS_URL"))
            .or_else(|_| env::var("NATS_URL"))
        {
            if !url.trim().is_empty() {
                orchestrator_config.nats.url = url;
            }
        }
        if let Ok(value) =
            env::var("ORCHESTRATOR_NATS_ENABLED").or_else(|_| env::var("CLOUD_NATS_ENABLED"))
        {
            orchestrator_config.nats.enabled = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }

        if orchestrator_config.database_url.is_empty() {
            return Err(anyhow::anyhow!(
                "DATABASE_URL is required (set via config file, ORCHESTRATOR_DATABASE_URL, or DATABASE_URL env var)"
            ));
        }
        if orchestrator_config.jwt_secret.is_empty() {
            return Err(anyhow::anyhow!(
                "JWT_SECRET is required (set via config file, ORCHESTRATOR_JWT_SECRET, or JWT_SECRET env var)"
            ));
        }
        if orchestrator_config.internal_api_key.is_empty() {
            return Err(anyhow::anyhow!(
                "ORCHESTRATOR_INTERNAL_API_KEY is required for orchestrator/cloud internal APIs"
            ));
        }
        if orchestrator_config.agent_provider.trim().is_empty() {
            orchestrator_config.agent_provider = default_agent_provider();
        }
        if orchestrator_config.agent_model.trim().is_empty() {
            orchestrator_config.agent_model = default_agent_model();
        }
        if orchestrator_config.agent_timeout_seconds == 0 {
            orchestrator_config.agent_timeout_seconds = default_agent_timeout_seconds();
        }
        if orchestrator_config.agent_max_iterations == 0 {
            orchestrator_config.agent_max_iterations = default_agent_max_iterations();
        }
        if orchestrator_config.db_max_connections == 0 {
            orchestrator_config.db_max_connections = default_db_max_connections();
        }
        if orchestrator_config.db_min_connections > orchestrator_config.db_max_connections {
            orchestrator_config.db_min_connections = orchestrator_config.db_max_connections;
        }
        if orchestrator_config.db_connect_timeout_seconds == 0 {
            orchestrator_config.db_connect_timeout_seconds = default_db_connect_timeout_seconds();
        }
        if orchestrator_config.db_acquire_timeout_seconds == 0 {
            orchestrator_config.db_acquire_timeout_seconds = default_db_acquire_timeout_seconds();
        }
        if orchestrator_config.db_idle_timeout_seconds == 0 {
            orchestrator_config.db_idle_timeout_seconds = default_db_idle_timeout_seconds();
        }
        if orchestrator_config.db_max_lifetime_seconds == 0 {
            orchestrator_config.db_max_lifetime_seconds = default_db_max_lifetime_seconds();
        }

        Ok(orchestrator_config)
    }

    fn load_discovery_observers(config: &ConfigBuilder, env_json: Option<&str>) -> Result<Vec<DiscoveryObserver>> {
        // An explicitly empty TOML list disables observers, even if the VM
        // deployment supplies an environment fallback.
        if config.get::<config::Value>("discovery_observers").is_ok() {
            return Ok(config.get("discovery_observers")?);
        }
        serde_json::from_str(env_json.filter(|s| !s.trim().is_empty()).unwrap_or("[]"))
            .context("invalid ORCHESTRATOR_DISCOVERY_OBSERVERS_JSON")
    }

    fn load_external_service_bindings(config: &ConfigBuilder, env_json: Option<&str>) -> Result<Vec<ExternalServiceBinding>> {
        let mut bindings: Vec<ExternalServiceBinding> = if config.get::<config::Value>("external_service_bindings").is_ok() {
            config.get("external_service_bindings")?
        } else {
            serde_json::from_str(env_json.filter(|s| !s.trim().is_empty()).unwrap_or("[]"))
                .context("invalid ORCHESTRATOR_EXTERNAL_SERVICE_BINDINGS_JSON")?
        };
        let mut identities = std::collections::HashSet::new();
        let mut service_deployments = std::collections::HashSet::new();
        for binding in &mut bindings {
            for value in [&mut binding.authority, &mut binding.health_origin] {
                let url = reqwest::Url::parse(value)?;
                anyhow::ensure!(matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
                    && url.path() == "/" && url.query().is_none() && url.fragment().is_none()
                    && url.username().is_empty() && url.password().is_none(), "external service URLs must be credential-free origins");
                *value = url.to_string();
            }
            anyhow::ensure!(!binding.service_id.trim().is_empty() && !binding.region.trim().is_empty(),
                "external service and region must be nonempty");
            anyhow::ensure!(service_deployments.insert((binding.service_id.clone(), binding.deployment_id.clone())),
                "duplicate external service deployment");
            anyhow::ensure!(identities.insert((binding.authority.clone(), binding.namespace.clone(), binding.deployment_id.clone())),
                "duplicate external service authority/namespace/deployment binding");
        }
        Ok(bindings)
    }

    fn get_config_path() -> Option<std::path::PathBuf> {
        if let Ok(config_path) = env::var("HEYO_ORCHESTRATOR_CONFIG_PATH") {
            return Some(std::path::PathBuf::from(config_path));
        }

        if let Ok(config_path) = env::var("HEYO_CONFIG_PATH") {
            return Some(std::path::PathBuf::from(config_path));
        }

        dirs::home_dir().map(|home| home.join(".heyo/orchestrator/orchestrator.toml"))
    }
}

fn default_regional_application_bake_seconds() -> u32 { 30 }

#[cfg(test)]
mod observer_config_tests {
    use super::*;

    #[test]
    fn multiple_deployments_can_share_a_region_but_not_an_identity() {
        let empty = ConfigBuilder::builder().build().unwrap();
        let mut values = serde_json::json!([
            {"service_id":"ci","region":"west","deployment_id":"ci-a","namespace":"default",
             "authority":"https://admin-a.test","health_origin":"https://ci-a.test","token_secret_path":"admin/token"},
            {"service_id":"ci","region":"west","deployment_id":"ci-b","namespace":"default",
             "authority":"https://admin-b.test","health_origin":"https://ci-b.test","token_secret_path":"admin/token"}
        ]);
        assert_eq!(Config::load_external_service_bindings(&empty, Some(&values.to_string())).unwrap().len(), 2);
        values[1]["deployment_id"] = serde_json::json!("ci-a");
        assert!(Config::load_external_service_bindings(&empty, Some(&values.to_string())).is_err());
    }

    #[test]
    fn managed_observer_env_is_a_fallback_not_a_file_override() {
        let empty = ConfigBuilder::builder().build().unwrap();
        assert!(Config::load_discovery_observers(&empty, None).unwrap().is_empty());
        assert!(Config::load_discovery_observers(&empty, Some("not json")).is_err());
        let json = r#"[{"service_id":"smoke","region":"us","deployment_id":"smoke","base_url":"https://admin.example","token_secret_path":"observer/token","discovery_token_secret":"reader"}]"#;
        let observers = Config::load_discovery_observers(&empty, Some(json)).unwrap();
        assert_eq!(observers[0].region, "us");
        assert_eq!(observers[0].discovery_token_secret.as_deref(), Some("reader"));
        let file = ConfigBuilder::builder()
            .add_source(File::from_str("discovery_observers = []", config::FileFormat::Toml)).build().unwrap();
        assert!(Config::load_discovery_observers(&file, Some(json)).unwrap().is_empty());
        assert!(Config::load_discovery_observers(&file, Some("invalid ignored fallback")).unwrap().is_empty());
    }
}

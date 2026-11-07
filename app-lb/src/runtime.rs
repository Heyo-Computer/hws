//! Which runtime boots a deployment's replicas.
//!
//! app-lb has two: heyvmd, which boots Firecracker/KVM microVMs
//! ([`crate::vm`]), and Incus, which boots system containers from OCI images
//! ([`crate::incus`]). This is the seam between them.
//!
//! **An enum, not a trait**, and the reason is that the two are not symmetric.
//! Thirteen of [`VmManager`]'s methods are heyvm-only — trees, catalog images,
//! proxy binds, the disk routes, mount export — and a trait would have to carry
//! all of them as `Err(Unsupported)` stubs on the Incus side, turning a fact the
//! compiler knows into one discovered at runtime. `VmManager` is also held by
//! value in six places, of which only the autoscaler needs the seam at all.
//! Callers that want the heyvm-only surface ask for it by name via
//! [`Runtime::heyvm`], and get a `VmManager` rather than a maybe.
//!
//! The shared vocabulary is the SDK's: [`SandboxInfo`], `SandboxStatus`,
//! `SandboxUsage`. Reusing it is what lets `promote_pending`, `prune`,
//! `routable_addr`, `is_terminal` and the dashboard work on containers without
//! knowing containers exist.

use crate::config::{Driver, LxcConfig, VmSpec};
use crate::incus::{Incus, IncusError};
use crate::vm::{VmError, VmManager, VmOwner, WorkspaceSeed};
use heyo_sdk::SandboxInfo;
use std::collections::HashMap;

/// Both runtimes, and the rule for choosing between them.
#[derive(Debug, Clone)]
pub struct Runtime {
    heyvm: VmManager,
    /// `None` when this host has no Incus, or app-lb cannot use the one it has.
    ///
    /// Not an error at construction. A host with no Incus is a fact about the
    /// host, and a fleet of microVMs must not care — so the absence is carried
    /// here and only surfaces when a `driver: lxc` deployment actually tries to
    /// scale, where it travels the create-failure path that already counts,
    /// reports and backs off.
    lxc: Option<Incus>,
}

impl Runtime {
    /// Build the seam. Synchronous and infallible, because `main` is both.
    ///
    /// The only question asked here is whether the socket is *there* — a cheap
    /// stat, and the difference between "this host does not run containers" and
    /// "Incus is broken". Whether it works is [`Self::probe_lxc`]'s question,
    /// asked once from the autoscaler's background service where there is a
    /// runtime to await on.
    pub fn new(heyvm: VmManager, lxc: LxcConfig) -> Self {
        let lxc = (lxc.enabled && lxc.socket.exists()).then(|| Incus::new(lxc));
        Self { heyvm, lxc }
    }

    /// Confirm Incus is reachable and trusts us, for the startup log.
    ///
    /// `None` when this host has no Incus at all, which is not news and should
    /// not be logged as though it were.
    pub async fn probe_lxc(&self) -> Option<Result<String, IncusError>> {
        Some(self.lxc.as_ref()?.probe().await)
    }

    /// heyvmd only — trees, catalog images, proxy binds, disks, mount export.
    ///
    /// A concrete `VmManager` rather than an `Option`, because every caller of
    /// these is a heyvm concept in the first place: the disk sweep walks
    /// heyvmd's data directory, and a container has nothing there.
    pub fn heyvm(&self) -> &VmManager {
        &self.heyvm
    }

    /// The Incus client, or the reason there isn't one — as a `VmError` so it
    /// joins the create-failure path already in place.
    fn require_lxc(&self) -> Result<&Incus, VmError> {
        self.lxc
            .as_ref()
            .ok_or_else(|| VmError::RuntimeUnavailable {
                driver: Driver::Lxc.as_str().to_string(),
                detail: "no usable Incus on this host; see the startup log for the socket \
                     app-lb tried"
                    .into(),
            })
    }

    /// Every sandbox both runtimes report.
    ///
    /// Merged rather than returned per-runtime because that is the shape the
    /// whole reconcile is written against: one fleet map, indexed by id, once
    /// per tick.
    ///
    /// **Each runtime's outcome is reported separately, and that is the point.**
    /// `reconcile` abandons the tick when the listing fails — the
    /// widest-blast-radius branch in the file — so folding two runtimes into one
    /// `Result` would let an unreachable heyvmd strand every container
    /// deployment, and an Incus that is briefly restarting strand every microVM.
    /// A runtime that answers is reconciled whatever the other one did.
    pub async fn list(&self) -> FleetListing {
        let mut sandboxes = Vec::new();

        let heyvm = match self.heyvm.list().await {
            Ok(mut infos) => {
                sandboxes.append(&mut infos);
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        };

        let lxc = match &self.lxc {
            None => None,
            Some(incus) => Some(match incus.list().await {
                Ok(mut infos) => {
                    sandboxes.append(&mut infos);
                    Ok(())
                }
                Err(e) => Err(e.to_string()),
            }),
        };

        FleetListing {
            sandboxes,
            heyvm,
            lxc,
        }
    }

    /// Create one replica and return its sandbox id, without waiting for boot.
    pub async fn create(
        &self,
        spec: &VmSpec,
        name: String,
        workspace: Option<&WorkspaceSeed>,
        owner: &VmOwner,
        secret_env: HashMap<String, String>,
        stateful: bool,
    ) -> Result<String, VmError> {
        match spec.driver {
            Driver::Lxc => self
                .require_lxc()?
                .create(spec, name, owner, secret_env)
                .await
                .map_err(|e| VmError::Runtime(e.to_string())),
            _ => self
                .heyvm
                .create(spec, name, workspace, owner, secret_env, stateful)
                .await
                .map(|sandbox| sandbox.sandbox_id().to_string()),
        }
    }

    /// Destroy a replica. One the runtime has already forgotten counts as gone.
    pub async fn kill(&self, driver: Driver, sandbox_id: &str) -> Result<(), VmError> {
        match driver {
            Driver::Lxc => self
                .require_lxc()?
                .kill(sandbox_id)
                .await
                .map_err(|e| VmError::Runtime(e.to_string())),
            _ => self.heyvm.kill(sandbox_id).await,
        }
    }
}

impl Runtime {
    /// Destroy a sandbox whose runtime is not known.
    ///
    /// The orphan paths — `adopt_existing` and `sweep_suspended` — kill
    /// sandboxes whose deployment is *gone*, so there is no spec left to read a
    /// driver from. Asking both runtimes is correct rather than lazy: at most
    /// one can hold a given id, `kill` treats an unknown sandbox as already
    /// destroyed on both, and the alternative — guessing — leaks whichever one
    /// guessed wrong.
    /// Stop a sandbox whose runtime is not known, keeping its disk.
    ///
    /// For sandboxes named for a deployment this LB does not have — see
    /// `Autoscaler::leave_unowned`. Asks both runtimes, for the reason
    /// [`kill_unknown`](Self::kill_unknown) does.
    pub async fn stop_unknown(&self, sandbox_id: &str) -> Result<(), VmError> {
        let heyvm = self.heyvm.suspend(sandbox_id).await;
        let lxc = match &self.lxc {
            Some(incus) => incus
                .stop_kept(sandbox_id)
                .await
                .map_err(|e| VmError::Runtime(e.to_string())),
            None => Ok(()),
        };
        match (heyvm, lxc) {
            (Ok(()), _) | (_, Ok(())) => Ok(()),
            (Err(e), Err(_)) => Err(e),
        }
    }

    pub async fn kill_unknown(&self, sandbox_id: &str) -> Result<(), VmError> {
        let heyvm = self.heyvm.kill(sandbox_id).await;
        let lxc = match &self.lxc {
            Some(incus) => incus
                .kill(sandbox_id)
                .await
                .map_err(|e| VmError::Runtime(e.to_string())),
            None => Ok(()),
        };
        // Only a failure everywhere is a failure: the runtime that does not hold
        // this sandbox reporting "no such sandbox" is the expected case.
        match (heyvm, lxc) {
            (Ok(()), _) | (_, Ok(())) => Ok(()),
            (Err(e), Err(_)) => Err(e),
        }
    }
}

/// One tick's view of the fleet, and which runtimes managed to produce it.
///
/// The per-runtime outcomes are kept apart rather than collapsed so a partial
/// fleet still reconciles — see [`Runtime::list`].
// `SandboxInfo` is neither `PartialEq` nor `Eq` upstream, so this is `Debug`
// only. Tests compare the fields they care about rather than whole listings.
#[derive(Debug, Clone)]
pub struct FleetListing {
    pub sandboxes: Vec<SandboxInfo>,
    /// heyvmd's own outcome. This is what the dashboard's "daemon unreachable"
    /// has always meant, so it stays its own field rather than becoming one
    /// entry in a list.
    pub heyvm: Result<(), String>,
    /// Incus's outcome, or `None` on a host that has no Incus — which is not a
    /// failure and must not be reported as one.
    pub lxc: Option<Result<(), String>>,
}

impl FleetListing {
    /// Every runtime this host has failed to answer. Only then is there nothing
    /// to reconcile and the tick is worth abandoning.
    pub fn total_outage(&self) -> bool {
        self.heyvm.is_err() && !matches!(self.lxc, Some(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LxcConfig;
    use crate::mounts::MountStore;

    fn heyvm() -> VmManager {
        VmManager::new(
            Some("http://127.0.0.1:1".into()),
            None,
            MountStore::new(std::path::PathBuf::from("/nonexistent/app-lb-mounts"), 0),
        )
        .unwrap()
    }

    /// **A host with no Incus must be a host that works.**
    ///
    /// This is the whole "must not break a Firecracker-only fleet" requirement.
    /// Construction is infallible and does no I/O, so app-lb starts normally on
    /// a machine that has never heard of Incus — and `main` stays synchronous,
    /// which it has to be because pingora's `Server` consumes it.
    #[test]
    fn a_host_with_no_incus_still_builds_a_runtime() {
        let runtime = Runtime::new(
            heyvm(),
            LxcConfig {
                socket: "/nonexistent/incus.socket".into(),
                ..LxcConfig::default()
            },
        );
        assert!(runtime.lxc.is_none());
        // ...and the heyvm half is untouched, which is what a microVM fleet needs.
        assert_eq!(runtime.heyvm().transport(), "http://127.0.0.1:1");
    }

    /// Explicitly off beats present. An operator who sets this has a reason, and
    /// a socket sitting on the filesystem should not override it.
    #[test]
    fn disabling_lxc_wins_over_a_socket_that_exists() {
        let socket = std::env::temp_dir().join(format!("app-lb-fake-incus-{}", std::process::id()));
        std::fs::write(&socket, b"").unwrap();

        let runtime = Runtime::new(
            heyvm(),
            LxcConfig {
                enabled: false,
                socket: socket.clone(),
                ..LxcConfig::default()
            },
        );
        assert!(runtime.lxc.is_none());

        std::fs::remove_file(&socket).ok();
    }

    /// An `lxc` deployment on a host with no Incus fails the *create*, and the
    /// error says whose problem it is.
    ///
    /// Deliberately not a registration failure: `validate` has no access to host
    /// config, and a spec is a statement of intent. Failing here puts it on the
    /// create-failure path that already counts, feeds and backs off.
    #[tokio::test]
    async fn an_lxc_create_without_incus_says_so_rather_than_failing_silently() {
        let runtime = Runtime::new(
            heyvm(),
            LxcConfig {
                socket: "/nonexistent/incus.socket".into(),
                ..LxcConfig::default()
            },
        );
        let spec: VmSpec = serde_json::from_value(serde_json::json!({
            "driver": "lxc", "image": "nginx:1.27", "port": 80,
        }))
        .unwrap();

        let err = runtime
            .create(
                &spec,
                "applb-web-01".into(),
                None,
                &VmOwner::default(),
                HashMap::new(),
                false,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, VmError::RuntimeUnavailable { .. }),
            "expected RuntimeUnavailable, got {err}",
        );
        // The message has to name the runtime, or the reader goes looking at
        // heyvmd for a container that was never going to touch it.
        assert!(err.to_string().contains("lxc"), "{err}");
    }

    /// A total outage is every runtime failing — not merely one. `reconcile`
    /// abandons the whole tick on this, so getting it wrong strands one
    /// runtime's deployments behind the other's downtime.
    #[test]
    fn only_a_total_outage_abandons_the_tick() {
        let listing = |heyvm: Result<(), String>, lxc: Option<Result<(), String>>| FleetListing {
            sandboxes: vec![],
            heyvm,
            lxc,
        };

        // heyvm down, containers fine: the container deployments still reconcile.
        assert!(!listing(Err("down".into()), Some(Ok(()))).total_outage());
        // Incus down, heyvm fine: the microVMs still reconcile.
        assert!(!listing(Ok(()), Some(Err("down".into()))).total_outage());
        // Nothing answered.
        assert!(listing(Err("down".into()), Some(Err("down".into()))).total_outage());
        // No Incus on this host at all is not an outage — but heyvm being down
        // still is, because then nothing answered.
        assert!(!listing(Ok(()), None).total_outage());
        assert!(listing(Err("down".into()), None).total_outage());
    }
}

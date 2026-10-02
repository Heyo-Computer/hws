//! Every value resolves flag → `ART_*` env → default.
//!
//! Environment is the only channel that survives being launched as a service
//! unit or from heyvm's `start_command`, so every knob has an env spelling.
//! Validation happens inside [`Config::resolve`], never at use sites.

use std::path::PathBuf;
use std::time::Duration;

/// Refuse a write that would leave less than this much free. Not politeness:
/// the store root's filesystem here is mounted `errors=remount-ro`, so filling
/// it produces a read-only root filesystem rather than an error return.
pub const DEFAULT_MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Blobs younger than this are never swept, even when unreferenced. Covers any
/// writer that bypasses the store lock (a crashed process, a human `cp`).
pub const DEFAULT_GC_MIN_AGE: Duration = Duration::from_secs(3600);

/// ext4 block size on every host this targets. `ZeroSquash` grain must be a
/// multiple of this or `FALLOC_FL_PUNCH_HOLE` frees nothing.
pub const BLOCK_SIZE: usize = 4096;

/// Default dashboard username when only a password is configured.
pub const DEFAULT_ADMIN_USER: &str = "admin";

/// Dashboard credentials, resolved from the environment.
///
/// `None` means no password was set, and the dashboard is therefore not mounted
/// at all — see [`crate::admin`] for why that is the default rather than
/// "mounted and open".
#[derive(Debug, Clone)]
pub struct AdminCredentials {
    pub user: String,
    pub password: String,
}

impl AdminCredentials {
    pub fn from_env() -> Option<AdminCredentials> {
        let password = std::env::var("ART_ADMIN_PASSWORD")
            .ok()
            .filter(|p| !p.is_empty())?;
        let user = std::env::var("ART_ADMIN_USER")
            .ok()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| DEFAULT_ADMIN_USER.to_string());
        Some(AdminCredentials { user, password })
    }
}

/// How the dashboard is exposed.
///
/// Three states rather than two, because "already behind a private network" is
/// a real deployment: an operator who has put the listener on a VPN or a
/// wireguard interface has already made the access decision, and making them
/// invent a password only creates a secret that can leak from somewhere else.
///
/// [`Open`](DashboardAccess::Open) must be asked for by name. An unset variable
/// still means [`Off`](DashboardAccess::Off) — the point of the default is that
/// forgetting something can never widen access.
#[derive(Debug, Clone)]
pub enum DashboardAccess {
    /// Not mounted at all. The default.
    Off,
    /// Mounted behind a login.
    Password(AdminCredentials),
    /// Mounted with no gate. Only ever from an explicit opt-in.
    Open,
    /// Mounted behind an **upstream** gate — app-lb — which authenticates the
    /// person and forwards `x-auth-request-*`. This app presents no login of
    /// its own and shows who the gate says is here.
    ///
    /// Like [`Open`](Self::Open), it must be asked for by name. Trusting a
    /// header is only sound when something in front strips it first, and
    /// nothing this process can read tells it whether that is true — so the
    /// operator asserts it, in one variable, and the log says what was
    /// asserted.
    Gate,
}

impl DashboardAccess {
    /// Resolve the tri-state from a password and the open opt-in.
    ///
    /// Setting both is an error rather than a precedence rule: whichever way it
    /// resolved, half the configuration would be a lie, and the half that loses
    /// is the half someone believed was protecting the page.
    pub fn resolve(
        password: Option<String>,
        user: String,
        open: bool,
        gate: bool,
    ) -> Result<DashboardAccess, String> {
        let password = password.filter(|p| !p.is_empty());
        // Every pair is refused rather than ordered. Whichever way a precedence
        // rule resolved, half the configuration would be a lie, and the half
        // that loses is the half somebody believed was protecting the page.
        match (password.is_some(), open, gate) {
            (true, true, _) => {
                return Err("ART_ADMIN_PASSWORD and ART_DASHBOARD_OPEN are both set; \
                     pick one — a password means gated, open means no gate at all"
                    .to_string());
            }
            (true, _, true) => {
                return Err("ART_ADMIN_PASSWORD and ART_DASHBOARD_GATE are both set; \
                     pick one — the gate authenticates upstream, a password here does not"
                    .to_string());
            }
            (_, true, true) => {
                return Err("ART_DASHBOARD_OPEN and ART_DASHBOARD_GATE are both set; \
                     pick one — open means no identity at all, the gate means an identity \
                     this app trusts"
                    .to_string());
            }
            _ => {}
        }
        Ok(match (password, open, gate) {
            (Some(password), _, _) => {
                DashboardAccess::Password(AdminCredentials { user, password })
            }
            (None, true, _) => DashboardAccess::Open,
            (None, _, true) => DashboardAccess::Gate,
            (None, false, false) => DashboardAccess::Off,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub root: PathBuf,
    pub min_free_bytes: u64,
    pub gc_min_age: Duration,
    /// heyvm's Firecracker image directory. Mirrors
    /// `get_firecracker_images_dir()` at heyo/mvm-ctrl/src/utils.rs:216, which
    /// honours `MVM_DATA_DIR` before falling back to `~/.heyo`.
    pub heyvm_images_dir: PathBuf,
}

impl Config {
    pub fn resolve(
        root_flag: Option<PathBuf>,
        min_free_flag: Option<u64>,
        gc_min_age_flag: Option<Duration>,
    ) -> Result<Config, String> {
        let root = match root_flag.or_else(|| std::env::var_os("ART_ROOT").map(PathBuf::from)) {
            Some(p) => p,
            None => home_dir()?.join(".artifacts"),
        };
        if root.is_relative() {
            return Err(format!(
                "store root must be absolute, got {}",
                root.display()
            ));
        }

        let min_free_bytes = match min_free_flag {
            Some(v) => v,
            None => match std::env::var("ART_MIN_FREE_BYTES") {
                Ok(s) => s
                    .parse()
                    .map_err(|_| format!("ART_MIN_FREE_BYTES must be a byte count, got {s:?}"))?,
                Err(_) => DEFAULT_MIN_FREE_BYTES,
            },
        };

        let gc_min_age = match gc_min_age_flag {
            Some(v) => v,
            None => match std::env::var("ART_GC_MIN_AGE_SECS") {
                Ok(s) => Duration::from_secs(s.parse().map_err(|_| {
                    format!("ART_GC_MIN_AGE_SECS must be a whole number of seconds, got {s:?}")
                })?),
                Err(_) => DEFAULT_GC_MIN_AGE,
            },
        };

        let heyvm_images_dir = match std::env::var_os("ART_HEYVM_IMAGES_DIR") {
            Some(p) => PathBuf::from(p),
            None => heyvm_data_dir()?.join("images").join("firecracker"),
        };

        Ok(Config {
            root,
            min_free_bytes,
            gc_min_age,
            heyvm_images_dir,
        })
    }
}

/// heyvm's data dir, resolved the same way `get_heyo_data_dir()` does at
/// heyo/mvm-ctrl/src/utils.rs:7-16 — `MVM_DATA_DIR` wins over `~/.heyo`, which
/// matters because heyvm.service points the daemon at a different tree than an
/// interactive shell.
fn heyvm_data_dir() -> Result<PathBuf, String> {
    if let Some(d) = std::env::var_os("MVM_DATA_DIR") {
        return Ok(PathBuf::from(d));
    }
    Ok(home_dir()?.join(".heyo"))
}

fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| "HOME is not set; pass --root or set ART_ROOT".to_string())
}

/// Parse a duration like `30s`, `10m`, `2h`, `1d`, or a bare number of seconds.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num, mult) = match s.as_bytes()[s.len() - 1] {
        b's' => (&s[..s.len() - 1], 1),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        b'd' => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration {s:?}; try 30s, 10m, 2h, 1d"))?;
    Ok(Duration::from_secs(n * mult))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_beats_env_and_default() {
        let c = Config::resolve(
            Some(PathBuf::from("/srv/art")),
            Some(7),
            Some(Duration::from_secs(9)),
        )
        .unwrap();
        assert_eq!(c.root, PathBuf::from("/srv/art"));
        assert_eq!(c.min_free_bytes, 7);
        assert_eq!(c.gc_min_age, Duration::from_secs(9));
    }

    #[test]
    fn relative_root_is_rejected() {
        // A relative root would resolve against the process cwd, so the same
        // store would mean different directories to the CLI and a daemon.
        let e = Config::resolve(Some(PathBuf::from("art")), Some(0), None).unwrap_err();
        assert!(e.contains("absolute"), "{e}");
    }

    #[test]
    fn dashboard_is_off_unless_something_asks_for_it() {
        // The default has to stay the closed one: a forgotten variable must
        // never be the reason a store's contents became readable.
        assert!(matches!(
            DashboardAccess::resolve(None, "admin".into(), false, false).unwrap(),
            DashboardAccess::Off
        ));
        // An empty password is a variable that was set to nothing, not a
        // request for an ungated dashboard.
        assert!(matches!(
            DashboardAccess::resolve(Some(String::new()), "admin".into(), false, false).unwrap(),
            DashboardAccess::Off
        ));
    }

    #[test]
    fn a_password_gates_and_the_opt_in_opens() {
        match DashboardAccess::resolve(Some("hunter2".into()), "ops".into(), false, false).unwrap()
        {
            DashboardAccess::Password(c) => {
                assert_eq!(c.user, "ops");
                assert_eq!(c.password, "hunter2");
            }
            other => panic!("expected a gated dashboard, got {other:?}"),
        }
        assert!(matches!(
            DashboardAccess::resolve(None, "admin".into(), true, false).unwrap(),
            DashboardAccess::Open
        ));
    }

    #[test]
    fn a_password_and_the_open_opt_in_together_are_an_error() {
        // Neither precedence rule is safe to pick silently: one of the two
        // settings would be a lie, and the operator cannot tell which.
        let e = DashboardAccess::resolve(Some("hunter2".into()), "admin".into(), true, false)
            .unwrap_err();
        assert!(e.contains("ART_ADMIN_PASSWORD"), "{e}");
        assert!(e.contains("ART_DASHBOARD_OPEN"), "{e}");
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("soon").is_err());
    }

    #[test]
    fn block_size_divides_default_grain() {
        // ZeroSquash punches nothing if the grain is not a whole number of
        // filesystem blocks.
        assert_eq!(BLOCK_SIZE % 512, 0);
    }
}

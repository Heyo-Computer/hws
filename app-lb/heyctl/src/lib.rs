//! A client for the [app-lb](https://github.com/sarocu/app-lb) admin API.
//!
//! app-lb is a load balancer for heyvm Firecracker/KVM microVMs. This crate
//! drives it: register deployments, scale pools, run commands inside a VM, and
//! attach an interactive shell.
//!
//! It is also the library behind the `heyctl` CLI, which is the point — the
//! CLI is this crate's first consumer, so a field the client stops understanding
//! becomes a compile error rather than a silently blank column at somebody's
//! terminal.
//!
//! ```no_run
//! # async fn f() -> hws::Result<()> {
//! use hws::{Client, ExecRequest};
//!
//! let lb = Client::builder("127.0.0.1:9090")
//!     .token(std::env::var("APP_LB_TOKEN").unwrap())
//!     .build()?;
//!
//! let out = lb.exec("sb-7f3a9c", &ExecRequest::new("uname -a")).await?;
//! println!("{}", out.stdout);
//! # Ok(()) }
//! ```
//!
//! # Authentication
//!
//! Prefer an **app-token**: scoped to particular deployments, revocable without
//! a restart, and optionally expiring. Basic auth also works and is unscoped —
//! it is the operator credential, and the one that mints tokens.
//!
//! ```no_run
//! # async fn f() -> hws::Result<()> {
//! use hws::{AdminScope, Client, NewToken};
//!
//! let admin = Client::builder("127.0.0.1:9090").basic("admin", "s3cret").build()?;
//! let minted = admin.mint_token(
//!     &NewToken::new("agent-runner")
//!         .admin(AdminScope::Admin)
//!         .for_deployments(["sb-7f3a9c"]),
//! ).await?;
//!
//! // The secret is in the reply and nowhere else, ever.
//! println!("{}", minted.token);
//! # Ok(()) }
//! ```
//!
//! A token scoped to specific deployments is refused the fleet-wide routes —
//! including minting — so it cannot widen itself.
//!
//! # Blocking callers
//!
//! Everything here is async. Under the `blocking` feature,
//! [`blocking::Client`] is the same surface with the `await`s taken out.
//!
//! # What this crate does *not* smooth over
//!
//! Three behaviours of app-lb are surprising enough that hiding them would be
//! worse than surfacing them:
//!
//! - A non-zero exit code from [`Client::exec`] is `Ok`, not `Err`. The command
//!   ran; it failed.
//! - `exec`'s timeout does not kill anything. It bounds app-lb's call to the
//!   daemon — on expiry you get [`Error::Upstream`] and the command **keeps
//!   running in the guest**.
//! - A shell socket has no resume. If it drops, the session is gone;
//!   reconnecting gives a *new* shell. See [`shell`].

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod api;
pub mod error;
pub mod shell;
pub mod transport;
pub mod types;
pub mod wait;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

pub use api::{Client, ClientBuilder, ExecRequest, Gates, MetricsQuery, NewToken};

/// The namespace an object belongs to when nothing says otherwise.
///
/// app-lb's own default, repeated here because the item routes for
/// namespace-scoped objects — an auth provider is `(namespace, name)` — need a
/// namespace in the *path*, so a client that omits `--namespace` still has to
/// name one.
pub const DEFAULT_NAMESPACE: &str = "default";
pub use error::{Credential, Error, Result};
pub use shell::{Shell, ShellEvent, ShellExit, ShellOptions};
pub use transport::{Auth, Transport};
pub use types::*;
pub use wait::{JobProgress, PoolProgress};

// -- CLI internals ----------------------------------------------------------
//
// Public only so `main.rs` can reach them across the lib/bin boundary. Not part
// of the supported surface, and `doc(hidden)` so they do not appear as though
// they were.

/// Read-modify-write helpers over a deployment spec as a `serde_json::Value`.
///
/// Public because they are genuinely useful to a caller assembling a spec, and
/// because writes go through `Value` by design — see [`api`].
pub mod spec;

#[cfg(feature = "config-file")]
#[cfg_attr(docsrs, doc(cfg(feature = "config-file")))]
pub mod config;

#[cfg(feature = "artifact")]
#[cfg_attr(docsrs, doc(cfg(feature = "artifact")))]
pub mod artifact;

#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod cmd;
#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod output;

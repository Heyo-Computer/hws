//! The JSON contract two pg-fc nodes speak to each other.
//!
//! Both nodes run the same binary, so this is one set of types rather than a
//! client half and a server half. It is also the one part of replication that
//! is a *versioned interface*: a node may be talking to a peer running an
//! older or newer build, and the failure mode of a silent mismatch here is a
//! pairing that half-exists on two hosts. Hence the round-trip test, and hence
//! `#[serde(default)]` on everything that was not in the first version.
//!
//! One request carries secrets — [`ProvisionReplica`], which hands the replica
//! both the tenant credential (so the same connection string works after a
//! promote) and the replication login. It must only ever travel over the
//! peer's authenticated admin API, and `Debug` is implemented by hand so a
//! stray log line cannot print either password.

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WriterClaimKind { Activation, InitialSource }

/// Exact, single-hop ownership assertion carried by the SQL upgrade request.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WriterClaim {
    pub kind: WriterClaimKind,
    pub database: String,
    pub generation: String,
    pub candidate_id: String,
    pub source_vm_id: String,
    pub system_identifier: String,
    pub pg_major: u32,
    pub sender_node: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterTunnelRequest {
    pub claim: WriterClaim,
    pub startup: Vec<u8>,
}

/// `GET /api/replication/peer/node` — the handshake before anything is
/// created, so a mismatch is a clean refusal rather than half a pairing.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeInfo {
    /// The peer's `PG_VM_POOL_NODE_NAME`. Compared against this node's own to
    /// refuse self-peering, which would otherwise produce a database
    /// subscribing to itself.
    pub node: String,
    /// Whether the peer has `PG_VM_POOL_REPLICATION` enabled at all.
    pub replication_enabled: bool,
    /// `server_version_num` of a VM the peer can reach, when it knows one.
    /// Used to refuse a publisher newer than its subscriber.
    #[serde(default)]
    pub server_version_num: Option<i32>,
    /// Whether the peer terminates TLS on its pooler listener. A primary
    /// refuses to hand out a credential to a replica that would send it in
    /// cleartext.
    #[serde(default)]
    pub tls: bool,
    /// The peer's pooler port, so an operator can sanity-check the peer record
    /// they typed against what the peer actually believes.
    #[serde(default)]
    pub pg_listen_port: Option<u16>,
    /// Explicit opt-in: old peers deserialize without this and are refused by
    /// physical preparation before either side creates a slot or VM.
    #[serde(default)]
    pub physical_prepare: bool,
    #[serde(default)]
    pub physical_handoff: bool,
    #[serde(default)]
    pub physical_successor: bool,
    #[serde(default)]
    pub physical_reseed: bool,
    #[serde(default)]
    pub physical_standby_bind: bool,
    /// Bootstrap standby binding preserves the ordinary tenant writer route.
    #[serde(default)]
    pub physical_standby_writer_routing: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PhysicalPrepareRequest { pub generation: String }

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PhysicalReseedRequest { pub generation: String, pub prior_generation: String }

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RetirePreviousRequest {
    pub generation: String,
    pub previous_vm_id: String,
    pub candidate_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RetirePreviousPeerRequest {
    pub standby: PhysicalStandbyBindRequest,
    pub previous_vm_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PhysicalStandbyBindRequest {
    pub database: String,
    pub generation: String,
    pub candidate_id: String,
    pub source_node: String,
    pub source_vm_id: String,
    pub system_identifier: String,
    pub pg_major: u32,
    pub source_lsn: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PhysicalHandoffRequest {
    pub database: String,
    pub generation: String,
    pub candidate_id: String,
    pub source_vm_id: String,
    pub system_identifier: String,
    pub pg_major: u32,
    pub barrier_lsn: String,
    pub source_node: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PhysicalHandoffGrantJson {
    pub database: String,
    pub generation: String,
    pub candidate_id: String,
    pub source_vm_id: String,
    pub system_identifier: String,
    pub pg_major: u32,
    pub barrier_lsn: String,
    pub peer: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PhysicalReplicaRequest {
    pub database: String,
    pub generation: String,
    #[serde(default)]
    pub predecessor: Option<String>,
    pub source_node: String,
    pub source_vm_id: String,
    pub system_identifier: String,
    pub pg_major: u32,
    pub source_lsn: String,
    pub settings: std::collections::BTreeMap<String, i32>,
    pub tenant: Login,
    pub repl: Login,
    pub primary: PrimaryEndpoint,
    pub slot: String,
    #[serde(default)]
    pub reseed_from: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PhysicalRecordJson {
    pub database: String,
    pub generation: String,
    pub phase: String,
    pub candidate_id: Option<String>,
    pub previous_vm_id: Option<String>,
    pub source_vm_id: String,
    #[serde(default)]
    pub source_node: String,
    #[serde(default)]
    pub system_identifier: String,
    #[serde(default)]
    pub pg_major: u32,
    #[serde(default)]
    pub previous_retirement: Option<super::physical_store::PreviousRetirement>,
    pub last_error: Option<String>,
}

impl From<&crate::replication::PhysicalRecord> for PhysicalRecordJson {
    fn from(r: &crate::replication::PhysicalRecord) -> Self { Self {
        database: r.database.clone(), generation: r.generation.clone(), phase: format!("{:?}", r.phase).to_lowercase(),
        candidate_id: r.candidate_id.clone(), previous_vm_id: r.previous_vm_id.clone(), source_vm_id: r.source_vm_id.clone(), last_error: r.last_error.clone(),
        source_node: r.source_node.clone(), system_identifier: r.system_identifier.clone(), pg_major: r.pg_major,
        previous_retirement: r.previous_retirement.clone(),
    }}
}

/// One end of the replication link, as the *other* node must dial it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrimaryEndpoint {
    /// An IPv4 literal, never a hostname: this is handed to a guest, and the
    /// microVMs ship with an empty `/etc/resolv.conf`. The primary resolves it
    /// host-side before sending.
    pub hostaddr: String,
    pub port: u16,
    pub sslmode: String,
}

impl std::fmt::Debug for PrimaryEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{} ({})", self.hostaddr, self.port, self.sslmode)
    }
}

/// A credential handed across the link.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Login {
    pub role: String,
    pub password: String,
}

/// Hand-written so neither password can reach a log through a `{:?}`.
impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Login {{ role: {:?}, password: *** }}", self.role)
    }
}

/// `POST /api/replication/peer/replicas` — the primary asking a peer to build
/// the replica. The only request that carries secrets.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProvisionReplica {
    pub database: String,
    /// The *primary's* node name, which becomes the replica's `peer`.
    pub peer: String,
    /// The tenant's own credential, mirrored onto the replica so the same
    /// connection string works against either node after a promote. This is
    /// what makes failover a DNS change rather than a re-credentialing.
    pub tenant: Login,
    /// The `REPLICATION` login the replica authenticates to the primary with.
    pub repl: Login,
    pub primary: PrimaryEndpoint,
    pub publication: String,
    pub subscription: String,
    pub slot: String,
    #[serde(default = "yes")]
    pub copy_data: bool,
    #[serde(default = "yes")]
    pub streaming: bool,
    /// The primary's `server_version_num`, so the replica can refuse a
    /// publisher newer than itself rather than fail obscurely at apply time.
    #[serde(default)]
    pub primary_server_version_num: Option<i32>,
}

fn yes() -> bool {
    true
}

/// A replication record as the API renders it. Carries no password — the only
/// place a password crosses is [`ProvisionReplica`].
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct RecordJson {
    pub database: String,
    pub role: String,
    pub peer: String,
    pub publication: String,
    pub subscription: String,
    pub slot: String,
    pub repl_role: String,
    pub state: String,
    pub message: String,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub fence: Option<FenceJson>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct FenceJson {
    #[serde(default = "hard_fence_mode")]
    pub mode: String,
    pub phase: String,
    pub message: String,
    pub vm_id: String,
    pub barrier_lsn: String,
    pub requested_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub sequences: Vec<crate::replication::SequenceSnapshot>,
}

fn hard_fence_mode() -> String { "hard".into() }

impl From<&crate::replication::ReplRecord> for RecordJson {
    fn from(r: &crate::replication::ReplRecord) -> Self {
        Self {
            database: r.database.clone(),
            role: r.role.as_str().to_string(),
            peer: r.peer.clone(),
            publication: r.publication.clone(),
            subscription: r.subscription.clone(),
            slot: r.slot.clone(),
            repl_role: r.repl_role.clone(),
            state: r.state.as_str().to_string(),
            message: r.message.clone(),
            created_at: r.created_at,
            updated_at: r.updated_at,
            fence: r.fence.as_ref().map(|f| FenceJson {
                mode: f.mode.clone(), phase: f.phase.clone(), message: f.message.clone(), vm_id: f.vm_id.clone(),
                barrier_lsn: f.barrier_lsn.clone(), requested_at: f.requested_at,
                updated_at: f.updated_at, sequences: f.sequences.clone(),
            }),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FenceResponse {
    pub record: RecordJson,
    pub database: String,
    pub vm_id: String,
    pub barrier_lsn: String,
}

/// What a primary can see about its own side of the link.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct PrimaryStatus {
    /// Whether a subscriber is currently attached to the slot. `false` with a
    /// growing `behind_bytes` is the shape that eventually fills the disk.
    pub slot_active: bool,
    /// `reserved` / `extended` / `unreserved` / `lost`. Anything but the first
    /// two means WAL the subscriber still needs is at risk or already gone.
    pub wal_status: Option<String>,
    pub behind_bytes: Option<i64>,
    pub current_lsn: Option<String>,
    pub confirmed_flush_lsn: Option<String>,
    pub sender_state: Option<String>,
    pub write_lag_s: Option<f64>,
    pub flush_lag_s: Option<f64>,
    pub replay_lag_s: Option<f64>,
}

/// What a replica can see about its own side.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct ReplicaStatus {
    pub enabled: bool,
    pub worker_running: bool,
    pub received_lsn: Option<String>,
    pub latest_end_lsn: Option<String>,
    pub last_msg_age_s: Option<f64>,
    pub tables_total: i64,
    pub tables_ready: i64,
}

/// `GET /api/replication/{db}` — the record plus whichever side this node can
/// see, plus whatever the peer reported when it was reachable.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct StatusJson {
    pub record: RecordJson,
    #[serde(default)]
    pub primary: Option<PrimaryStatus>,
    #[serde(default)]
    pub replica: Option<ReplicaStatus>,
    /// Why the peer could not be reached, if it could not. A dead peer renders
    /// as a message on the page, never a hung request.
    #[serde(default)]
    pub peer_error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PromoteResponse {
    pub record: RecordJson,
    /// How many sequences were re-seeded. Logical replication carries no
    /// sequence values, so this is the number that would otherwise have
    /// collided on the first insert after the promote.
    pub sequences_fixed: i64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DetachResponse {
    pub record: RecordJson,
    pub slot_dropped: bool,
    pub publication_dropped: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_peer_does_not_claim_writer_preserving_standby_support() {
        let info: NodeInfo = serde_json::from_value(serde_json::json!({
            "node": "peer", "replication_enabled": true, "tls": true,
            "physical_standby_bind": true,
        })).unwrap();
        assert!(info.physical_standby_bind);
        assert!(!info.physical_standby_writer_routing);
    }

    fn provision() -> ProvisionReplica {
        ProvisionReplica {
            database: "acme".into(),
            peer: "node_a".into(),
            tenant: Login {
                role: "acme".into(),
                password: "tenantpassword".into(),
            },
            repl: Login {
                role: "acme_pgfcrepl".into(),
                password: "replpassword12".into(),
            },
            primary: PrimaryEndpoint {
                hostaddr: "203.0.113.10".into(),
                port: 6432,
                sslmode: "require".into(),
            },
            publication: "pgfc_pub_acme".into(),
            subscription: "pgfc_sub_acme".into(),
            slot: "pgfc_acme_node_b".into(),
            copy_data: true,
            streaming: true,
            primary_server_version_num: Some(160004),
        }
    }

    /// The cross-node contract: two nodes on different builds must agree, and
    /// a silent mismatch here leaves a pairing half-created on two hosts.
    #[test]
    fn provision_request_round_trips() {
        let a = provision();
        let json = serde_json::to_string(&a).unwrap();
        let b: ProvisionReplica = serde_json::from_str(&json).unwrap();
        assert_eq!(b.database, a.database);
        assert_eq!(b.repl.password, a.repl.password);
        assert_eq!(b.primary, a.primary);
        assert_eq!(b.slot, a.slot);
    }

    /// An older peer that has never heard of the newer optional fields must
    /// still be understood, and must default to the safe//previous behaviour.
    #[test]
    fn optional_fields_default_for_an_older_peer() {
        let minimal = r#"{"database":"acme","peer":"node_a",
            "tenant":{"role":"acme","password":"p"},
            "repl":{"role":"acme_pgfcrepl","password":"q"},
            "primary":{"hostaddr":"10.0.0.1","port":6432,"sslmode":"require"},
            "publication":"p","subscription":"s","slot":"sl"}"#;
        let r: ProvisionReplica = serde_json::from_str(minimal).unwrap();
        assert!(
            r.copy_data,
            "an older peer means the original behaviour: seed the data"
        );
        assert!(r.streaming);
        assert_eq!(r.primary_server_version_num, None);

        let n: NodeInfo =
            serde_json::from_str(r#"{"node":"b","replication_enabled":true}"#).unwrap();
        assert!(!n.tls, "unknown means do not assume TLS");
        assert_eq!(n.server_version_num, None);
    }

    #[test]
    fn physical_status_supplies_handoff_identity_without_credentials() {
        let record = crate::replication::PhysicalRecord {
            database: "acme".into(), generation: "g1".into(), predecessor: None,
            candidate_name: "repl-seed-g1".into(), candidate_id: Some("candidate-e1".into()),
            previous_vm_id: Some("old-e0".into()), source_node: "us3".into(), source_vm_id: "source-u0".into(),
            system_identifier: "7431234567890123456".into(), pg_major: 18, slot: "physical_acme".into(),
            phase: crate::replication::PhysicalPhase::Verified, handoff_barrier: None, standby_lsn: None, previous_retirement: None, last_error: None,
            repl: Some(Login { role: "repl_acme".into(), password: "not-for-status".into() }),
        };
        let mut value = serde_json::to_value(PhysicalRecordJson::from(&record)).unwrap();
        assert!(!value.to_string().contains("not-for-status"));
        assert!(!value.to_string().contains("repl_acme"));
        value["barrier_lsn"] = "0/0".into();
        let request: PhysicalHandoffRequest = serde_json::from_value(value).unwrap();
        assert_eq!(request.source_node, "us3");
        assert_eq!(request.source_vm_id, "source-u0");
        assert_eq!(request.candidate_id, "candidate-e1");
        assert_eq!(request.system_identifier, "7431234567890123456");
        assert_eq!(request.pg_major, 18);
    }

    /// Both passwords cross the wire in this one struct; neither may reach a
    /// log through a `{:?}` on it or on anything containing it.
    #[test]
    fn debug_never_prints_a_password() {
        let d = format!("{:?}", provision());
        assert!(!d.contains("tenantpassword"), "{d}");
        assert!(!d.contains("replpassword12"), "{d}");
        assert!(
            d.contains("acme_pgfcrepl"),
            "roles are still identifiable: {d}"
        );
    }
}

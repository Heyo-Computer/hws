//! Permanent controller retirement, not application quiescence or CI ownership.
//! The caller approves exact runtime identities. Unknown work never authorizes a
//! replacement target, retry allocation, record removal, or storage destruction.
use crate::{config::DeploymentSpec, deployment::Deployment, registry::Registry};
use serde::{Deserialize,Serialize};
use std::{collections::{BTreeMap,BTreeSet},sync::Arc};

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Target {
    pub backend_server_id:String,
    pub backend_sandbox_id:String,
    #[serde(deserialize_with="creation_nanos")]
    pub created_at_unix_nanos:String,
    pub libvirt_connection_uri:String,
    pub libvirt_domain_uuid:String,
}

fn creation_nanos<'de,D:serde::Deserializer<'de>>(deserializer:D)->Result<String,D::Error> {
    let value=String::deserialize(deserializer)?;
    if !valid_creation_nanos(&value) {return Err(serde::de::Error::custom("creation nanos require a canonical positive decimal u128 string"));}
    Ok(value)
}

fn valid_creation_nanos(value:&str)->bool {
    !value.starts_with('0') && value.bytes().all(|b|b.is_ascii_digit())
        && value.parse::<u128>().is_ok_and(|n|n>0)
}

#[derive(Clone,Debug,PartialEq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation_id:String,
    pub expected_revision:String,
    pub expected_spec_sha256:String,
    pub targets:Vec<Target>,
}

#[derive(Clone,Debug,Default,PartialEq,Serialize,Deserialize)]
pub struct CreateAttempt {
    pub name:String,
    pub sandbox_id:Option<String>,
    #[serde(default, skip_serializing_if="Option::is_none")]
    pub allocation:Option<crate::allocation::Intent>,
    #[serde(default, skip_serializing_if="Option::is_none")]
    pub receipt:Option<crate::allocation::Receipt>,
    #[serde(default, skip_serializing_if="Option::is_none")]
    pub seed_digest:Option<String>,
    #[serde(default)]
    pub seed_mount_index:usize,
    /// Provisioning placeholders do not prove the queued create finished.
    #[serde(default)]
    pub runtime_observed:bool,
}

#[derive(Clone,Debug,PartialEq,Serialize,Deserialize)]
pub struct Operation {
    pub request:Request,
    pub spec:DeploymentSpec,
    pub inventory:Vec<String>,
    pub state:String,
    pub receipts:BTreeMap<String,serde_json::Value>,
    pub unresolved:Option<String>,
}

fn save(registry:&Registry,d:&Deployment,op:Operation)->Result<(),String> {
    let terminal=op.state=="retired";
    let mut state=(*d.state()).clone(); state.retirement=Some(op);
    // Retain the in-memory freeze even if rename/fsync has an uncertain result.
    // A completed receipt is published only after durable persistence.
    if !terminal {d.set_state(state.clone());}
    for backend in d.backends().iter() {backend.set_draining(true);}
    registry.persist_snapshot(d,&state).map_err(|_|"retirement persistence unresolved".to_string())?;
    if terminal {d.set_state(state);}
    Ok(())
}

/// Caller holds the exclusive controller lease and registry writer. It waits
/// out every admitted create/worker before taking this exact inventory snapshot.
pub fn freeze(registry:&Registry,d:&Arc<Deployment>,request:Request)->Result<Operation,String> {
    if let Some(existing)=&d.state().retirement {
        if existing.request!=request {return Err("retirement request changed".into());}
        save(registry,d,existing.clone())?;
        return Ok(existing.clone());
    }
    if !d.spec.is_managed() || request.expected_revision!=d.state().rollout_revision
        || request.expected_spec_sha256!=crate::rollout::fingerprint(&d.spec)
        || request.operation_id.is_empty() || request.operation_id.len()>128
        || !request.operation_id.bytes().all(|b|b.is_ascii_alphanumeric()||b"-_".contains(&b))
        || request.targets.is_empty() || request.targets.len()>128 {
        return Err("retirement requires a managed deployment, current revision and exact targets".into());
    }
    let mut approved=BTreeSet::new();
    for target in &request.targets {
        if !valid_creation_nanos(&target.created_at_unix_nanos) || [&target.backend_server_id,&target.backend_sandbox_id,
            &target.libvirt_connection_uri,&target.libvirt_domain_uuid].iter().any(|s|s.is_empty()||s.len()>1024)
            || !target.backend_sandbox_id.bytes().all(|b|b.is_ascii_alphanumeric()||b"-_".contains(&b))
            || !approved.insert(target.backend_sandbox_id.clone()) {
            return Err("invalid or duplicate retirement target".into());
        }
    }
    let inventory:BTreeSet<String>=d.backends().iter().map(|b|b.sandbox_id.clone())
        .chain(d.pending().iter().map(|p|p.sandbox_id.clone()))
        .chain(d.state().suspended.iter().cloned())
        .chain(d.state().create_attempts.iter().filter_map(|a|a.sandbox_id.clone())).collect();
    let unresolved=if inventory!=approved {Some("approved targets differ from exact controller inventory".into())} else {None};
    let op=Operation {request,spec:d.spec.clone(),inventory:inventory.into_iter().collect(),
        state:"frozen".into(),receipts:BTreeMap::new(),unresolved};
    save(registry,d,op.clone())?; Ok(op)
}

#[async_trait::async_trait]
pub trait Backend:Send+Sync {
    async fn status(&self,target:&Target)->Result<serde_json::Value,String>;
    async fn retire(&self,operation:&str,target:&Target)->Result<serde_json::Value,String>;
}

fn receipt(value:&serde_json::Value,operation:&str,target:&Target)->bool {
    value["state"]=="retired" && value["request"]==serde_json::json!({"operationId":operation,"target":target})
        && value["retiredAt"].as_str().is_some_and(|s|s.len()<=64 && chrono::DateTime::parse_from_rfc3339(s).is_ok())
}

/// Progress only the frozen target set. GET pending is not a fencing receipt.
/// No automatic retries: a later explicit POST replays the same durable intent.
pub async fn advance(registry:&Registry,d:&Arc<Deployment>,backend:&impl Backend,blocked:Option<String>)->Result<Operation,String> {
    let mut op=d.state().retirement.clone().ok_or("retirement missing")?;
    if op.state=="retired" {return Ok(op);}
    if op.unresolved.is_some() {return Ok(op);}
    let state=d.state();
    let blocker=blocked.or_else(||state.create_attempts.iter().any(|a|a.sandbox_id.is_none())
        .then(||"allocation outcome is ambiguous; no retirement success is possible".into()))
        .or_else(||state.create_attempts.iter().any(|a| a.allocation.as_ref().is_some_and(|intent|
            !a.runtime_observed || a.receipt.as_ref().is_none_or(|receipt|
                !intent.accepts(receipt) || a.sandbox_id.as_ref() != Some(&receipt.sandbox_id))))
            .then(||"correlated allocation requires a matching receipt and observed runtime".into()))
        .or_else(||(!state.allocation_history_complete)
            .then(||"legacy allocation history is not authoritative, even after successful create; explicit reconciliation is required".into()))
        .or_else(||(!state.rollouts.is_empty() || state.route_handoff.is_some())
            .then(||"rollout or route handoff requires explicit reconciliation".into()));
    if let Some(reason)=blocker {op.unresolved=Some(reason); save(registry,d,op.clone())?; return Ok(op);}
    // Persistence failures must be retried before *any* backend operation.
    op.state="retiring".into(); save(registry,d,op.clone())?;
    for target in &op.request.targets {
        if op.receipts.contains_key(&target.backend_sandbox_id) {continue;}
        let observed=backend.status(target).await?;
        if observed["target"]!=serde_json::to_value(target).unwrap() {return Err("backend retirement target mismatch".into());}
        let record=match observed["state"].as_str() {
            Some("retired")=>observed["receipt"].clone(),
            Some("active"|"retiring")=>backend.retire(&op.request.operation_id,target).await?,
            _=>return Err("backend retirement state unknown".into()),
        };
        if !receipt(&record,&op.request.operation_id,target) {return Err("backend did not attest exact completed retirement".into());}
        op.receipts.insert(target.backend_sandbox_id.clone(),record);
        save(registry,d,op.clone())?;
    }
    op.state="retired".into(); save(registry,d,op.clone())?; Ok(op)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn correlated_retirement_requires_observed_runtime_and_matching_saved_receipt() {
        struct ExactBackend(std::sync::atomic::AtomicUsize);
        #[async_trait::async_trait]
        impl Backend for ExactBackend {
            async fn status(&self, target:&Target)->Result<serde_json::Value,String> {
                self.0.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
                Ok(serde_json::json!({"target":target,"state":"active"}))
            }
            async fn retire(&self, operation:&str,target:&Target)->Result<serde_json::Value,String> {
                Ok(serde_json::json!({"request":{"operationId":operation,"target":target},
                    "state":"retired","retiredAt":"2026-09-25T10:00:00Z"}))
            }
        }
        for case in 0..5 {
            let root=tempfile::tempdir().unwrap();
            let registry=Registry::new(root.path().join("state.json"));
            let d=registry.upsert(serde_json::from_value(serde_json::json!({
                "id":"service","routes":[],"vm":{"driver":"kvm","port":8080,"correlated_creates":true},
                "scaling":{"min_replicas":0,"warm_pool":0}
            })).unwrap());
            let id="sb-0123456789abcdef0123456789abcdef";
            let intent=crate::allocation::Intent {operation_id:"create-1".into(),request_digest:"r".into(),
                backend_request_digest:"b".into(),transport:"http://daemon".into()};
            let mut receipt=crate::allocation::Receipt {operation_id:"create-1".into(),sandbox_id:id.into(),
                request_digest:"r".into(),backend_request_digest:"b".into()};
            if case==2 {receipt.request_digest="wrong".into();}
            if case==3 {receipt.sandbox_id="sb-ffffffffffffffffffffffffffffffff".into();}
            d.mutate_state(|s|s.create_attempts.push(CreateAttempt {sandbox_id:Some(id.into()),
                allocation:Some(intent),receipt:(case!=1).then_some(receipt),runtime_observed:case!=0,
                ..Default::default()}));
            let request:Request=serde_json::from_value(serde_json::json!({
                "operation_id":"retire-1","expected_revision":d.state().rollout_revision,
                "expected_spec_sha256":crate::rollout::fingerprint(&d.spec),"targets":[{
                    "backendServerId":"host-1","backendSandboxId":id,"createdAtUnixNanos":"12345",
                    "libvirtConnectionUri":"qemu:///system","libvirtDomainUuid":"domain-1"
                }]
            })).unwrap();
            freeze(&registry,&d,request).unwrap();
            let backend=ExactBackend(std::sync::atomic::AtomicUsize::new(0));
            let result=advance(&registry,&d,&backend,None).await.unwrap();
            assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst),usize::from(case==4));
            assert_eq!(result.state=="retired",case==4);
            assert_eq!(result.unresolved.is_some(),case!=4);
        }
    }

    #[test]
    fn retirement_private_wire_uses_exact_decimal_u128_strings_never_numbers() {
        // Private Target serializes SystemTime nanos with as_nanos().to_string().
        // Deliberately exceed u64 to catch narrowing and JSON-number conversions.
        let wire=serde_json::json!({"backendServerId":"host-1","backendSandboxId":"sb-1",
            "createdAtUnixNanos":"18446744073709551616","libvirtConnectionUri":"qemu:///system",
            "libvirtDomainUuid":"00000000-0000-0000-0000-000000000001"});
        let target:Target=serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(&target).unwrap(),wire);
        let record=serde_json::json!({"request":{"operationId":"retire-1","target":wire},
            "state":"retired","retiredAt":"2026-09-25T10:00:00Z"});
        assert!(receipt(&record,"retire-1",&target));
        let mut numeric=wire.clone();numeric["createdAtUnixNanos"]=serde_json::json!(1780000000123456789_u64);
        assert!(serde_json::from_value::<Target>(numeric).is_err());
        for invalid in ["","0","01","+1","-1","1.0","1e9"," 1","340282366920938463463374607431768211456"] {
            let mut bad=wire.clone();bad["createdAtUnixNanos"]=serde_json::json!(invalid);
            assert!(serde_json::from_value::<Target>(bad).is_err(),"{invalid}");
        }
        let mut maximum=wire;maximum["createdAtUnixNanos"]=serde_json::json!(u128::MAX.to_string());
        assert!(serde_json::from_value::<Target>(maximum).is_ok());
    }

    #[test]
    fn retirement_lock_corrupt_startup_and_persistence_failure_never_reopen() {
        let root=tempfile::tempdir().unwrap();
        let registry=Registry::new(root.path().join("state.json"));
        let lock=registry.controller_lock().unwrap();
        let other=Registry::new(root.path().join("state.json"));
        assert!(other.controller_lock().is_err());
        // Parallel tests spawn children. On Linux a fork temporarily inherits
        // this open file description until exec; closing our descriptor alone
        // need not release its flock immediately. Release explicitly here so
        // the next acquisition tests unlock, not unrelated child scheduling.
        lock.unlock().unwrap();
        drop(lock);
        let _next_lock=other.controller_lock().unwrap();
        let d=registry.upsert(serde_json::from_value(serde_json::json!({
            "id":"service","routes":[],"vm":{"driver":"kvm","port":8080},
            "scaling":{"min_replicas":0,"warm_pool":0}
        })).unwrap());
        d.set_pending(vec![crate::deployment::PendingVm::new("sb-1".into())]);
        let request:Request=serde_json::from_value(serde_json::json!({
            "operation_id":"freeze-1","expected_revision":d.state().rollout_revision,
            "expected_spec_sha256":crate::rollout::fingerprint(&d.spec),"targets":[{
                "backendServerId":"host-1","backendSandboxId":"sb-1","createdAtUnixNanos":"12345",
                "libvirtConnectionUri":"qemu:///system","libvirtDomainUuid":"00000000-0000-0000-0000-000000000001"
            }]
        })).unwrap();
        registry.fail_after_rename.store(true,std::sync::atomic::Ordering::SeqCst);
        assert!(freeze(&registry,&d,request.clone()).is_err());
        assert!(registry.retirement_frozen("service"));
        assert!(registry.update(d.spec.clone()).is_none());
        assert!(registry.remove("service").is_none());
        assert!(registry.forget("service").is_err());
        assert!(Arc::ptr_eq(&registry.upsert(d.spec.clone()),&d));
        let mut op=freeze(&registry,&d,request).unwrap();
        op.state="retired".into();
        registry.fail_after_rename.store(true,std::sync::atomic::Ordering::SeqCst);
        assert!(save(&registry,&d,op).is_err());
        assert_eq!(d.state().retirement.as_ref().unwrap().state,"frozen","never publish unpersisted completion");
        registry.load().unwrap();
        assert_eq!(d.state().retirement.as_ref().unwrap().state,"frozen","reload cannot replace local freeze");
        std::fs::write(registry.state_dir().join("service.json"),b"unreadable state").unwrap();
        let restarted=Registry::new(root.path().join("state.json"));
        assert_eq!(restarted.load().unwrap(),0);
        assert!(restarted.require_complete_load().is_err());
        assert_eq!(restarted.sweep_orphan_state().unwrap(),0);
        assert_eq!(std::fs::read(registry.state_dir().join("service.json")).unwrap(),b"unreadable state");
    }
}

#![cfg(feature = "cli")]
//! Exercise the real binary, authentication, HTTP transport and renderers.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

fn invoke(args: &[&str], response: &str) -> (String, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let response = response.to_owned();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = socket.read(&mut buf).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buf[..n]);
            if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .unwrap_or("0")
                    .parse()
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
        }
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    let result = Command::new(env!("CARGO_BIN_EXE_heyctl"))
        .args([
            "--server",
            &format!("http://{address}/proxy"),
            "--token",
            "test-recovery-token",
            "--config",
            "/dev/null",
            "recovery",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let request = server.join().unwrap();
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer test-recovery-token\r\n")
    );
    (request, String::from_utf8(result.stdout).unwrap())
}

#[test]
fn binary_proxy_requests_and_output_contract() {
    let (request, table) = invoke(
        &["checkpoints", "vm/a?b"],
        r#"[{"checkpoint_id":"cp","state":"committed","committed_at":1755820800,"created_at":1755820800,"backend_id":"us3","runtime_id":"rt"}]"#,
    );
    assert!(request.starts_with("GET /proxy/api/vm-recovery/vm%2Fa%3Fb/checkpoints HTTP/1.1"));
    assert!(table.contains("2025-08-22 00:00:00 UTC"));
    let (request, json) = invoke(
        &["destinations", "vm", "-o", "json"],
        r#"{"sandbox_id":"sb","source_backend_id":"us3","destinations":[{"id":"eu1","region":"eu1","eligible":false,"reason":"capacity"}]}"#,
    );
    assert!(request.starts_with("GET /proxy/api/vm-recovery/vm/destinations "));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap()["destinations"][0]["reason"],
        "capacity"
    );
    let (request, yaml) = invoke(&["list", "vm", "-o", "yaml"], "[]");
    assert!(request.starts_with("GET /proxy/api/vm-recovery/vm/recoveries "));
    assert!(
        serde_yaml::from_str::<Vec<serde_json::Value>>(&yaml)
            .unwrap()
            .is_empty()
    );
    let (request, _) = invoke(&["status", "vm/a", "op/b"], "{}");
    assert!(request.starts_with("GET /proxy/api/vm-recovery/vm%2Fa/recoveries/op%2Fb "));
    let uuid = "12345678-1234-1234-1234-123456789abc";
    let args = [
        "start",
        "vm",
        "--checkpoint",
        uuid,
        "--destination",
        "eu1",
        "--source-fenced",
        "--fencing-evidence",
        "power disabled",
        "--operation-id",
        uuid,
        "-o",
        "json",
    ];
    let (first, _) = invoke(&args, "{}");
    let (second, _) = invoke(&args, "{}");
    assert!(first.starts_with("POST /proxy/api/vm-recovery/vm/recoveries "));
    let body = |request: String| request.split_once("\r\n\r\n").unwrap().1.to_owned();
    assert_eq!(body(first), body(second));
}

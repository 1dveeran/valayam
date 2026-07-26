use serde_json::json;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use test_runner::*;

fn start_dummy_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = [0; 1024];
                let _ = stream.read(&mut buffer);
                let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}";
                let _ = stream.write_all(response.as_bytes());
            }
        }
    });

    format!("http://127.0.0.1:{}", port)
}

#[test]
fn stub_dependency_audit() {
    let wasm = build_wasm("valayam-plugin-dependency-audit");
    let target_url = start_dummy_server();
    let input = WasmInput {
        template: json!({"id": "dep", "name": "Dependency"}),
        context: HashMap::from([("TARGET_URL".into(), target_url)]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn stub_graphql_audit() {
    let wasm = build_wasm("valayam-plugin-graphql-audit");
    let target_url = start_dummy_server();
    let input = WasmInput {
        template: json!({"id": "graphql", "name": "GraphQL"}),
        context: HashMap::from([("TARGET_URL".into(), target_url)]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn stub_iot_audit() {
    let wasm = build_wasm("valayam-plugin-iot-audit");
    let target_url = start_dummy_server();
    let input = WasmInput {
        template: json!({"id": "iot", "name": "IoT"}),
        context: HashMap::from([("TARGET_URL".into(), target_url)]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn stub_mobile_audit() {
    let wasm = build_wasm("valayam-plugin-mobile-audit");
    let target_url = start_dummy_server();
    let input = WasmInput {
        template: json!({"id": "mobile", "name": "Mobile"}),
        context: HashMap::from([("TARGET_URL".into(), target_url)]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn stub_oauth_audit() {
    let wasm = build_wasm("valayam-plugin-oauth-audit");
    let target_url = start_dummy_server();
    let input = WasmInput {
        template: json!({"id": "oauth", "name": "OAuth"}),
        context: HashMap::from([("TARGET_URL".into(), target_url)]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}
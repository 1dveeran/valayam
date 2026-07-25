use serde_json::json;
use std::collections::HashMap;
use valayam_plugin_test_runner::*;

fn empty_ctx() -> HashMap<String, String> {
    HashMap::new()
}

#[test]
fn stub_dependency_audit() {
    let wasm = build_wasm("valayam-plugin-dependency-audit");
    let input = WasmInput {
        template: json!({"id": "dep", "name": "Dep"}),
        context: HashMap::from([("TARGET_URL".into(), "".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn stub_graphql_audit() {
    let wasm = build_wasm("valayam-plugin-graphql-audit");
    let input = WasmInput {
        template: json!({"id": "gql", "name": "GQL"}),
        context: HashMap::from([("TARGET_URL".into(), "".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn stub_iot_audit() {
    let wasm = build_wasm("valayam-plugin-iot-audit");
    let input = WasmInput {
        template: json!({"id": "iot", "name": "IoT"}),
        context: HashMap::from([("TARGET_URL".into(), "".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn stub_mobile_audit() {
    let wasm = build_wasm("valayam-plugin-mobile-audit");
    let input = WasmInput {
        template: json!({"id": "mobile", "name": "Mobile"}),
        context: HashMap::from([("TARGET_URL".into(), "".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}

#[test]
fn stub_oauth_audit() {
    let wasm = build_wasm("valayam-plugin-oauth-audit");
    let input = WasmInput {
        template: json!({"id": "oauth", "name": "OAuth"}),
        context: HashMap::from([("TARGET_URL".into(), "".into())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(!out.matched);
}
# Valayam Helper

This document provides examples on how to use the `valayam` scanner, specifically focusing on interacting with its new Extism-backed WASM plugin architecture.

## Getting Help

```bash
cargo run --bin valayam-cli -- --help
```

## CLI Flags

| Flag | Short | Description |
|---|---|---|
| `--target` | `-u` | Target Base URL (default: `https://httpbin.org`) |
| `--template` | `-t` | Path to Native YAML template file or directory |
| `--plugin` | `-p` | Path to a precompiled `.wasm` plugin to execute |
| `--output` | `-o` | Path to write JSON output to |
| `--rate-limit` | `-r` | Max requests per second (default: unlimited) |
| `--proxy-file` | | Path to proxy list file (one per line) |
| `--worker` | | Target worker node URI (e.g. `http://localhost:50051`) |

## Running Scans (Dynamic Plugins)

In the new Valayam architecture, scanning logic is delegated to `.wasm` plugins rather than monolithic engine features. 

### Basic Execution via Plugin Flag

You can directly test a compiled WASM plugin against a target:

```bash
cargo run --bin valayam-cli -- -u https://example.com -p ./plugins-wasm/target/wasm32-unknown-unknown/debug/valayam_plugin_api_audit.wasm
```

### Template-Driven Plugin Execution

YAML templates are still supported for orchestration, but they now instruct the engine which plugins to load and what parameters to pass via the `WasmInput` context.

```bash
# Execute all templates in a directory (the templates define which plugins to load)
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo/

# Save findings to JSON
cargo run --bin valayam-cli -- -t ./templates_repo/ -o results.json
```

---

## Developing & Testing Custom WASM Plugins

Developers can create their own scanning capabilities using the `valayam-plugin-sdk`.

### 1. Generating a new Plugin
```bash
cargo new --lib plugins-wasm/my-custom-audit
```

Update `Cargo.toml`:
```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
valayam-plugin-sdk = { path = "../../crates/valayam-plugin-sdk" }
extism-pdk = "1.4"
serde_json = "1.0"
```

### 2. Testing Plugins Locally

We provide a specialized `valayam-plugin-test-runner` crate to allow developers to rapidly test their WASM modules without needing to boot the full CLI or Engine stack.

```rust
// Inside your plugin's tests (e.g. `tests/my_plugin_tests.rs`)
use valayam_plugin_test_runner::*;
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_my_custom_plugin() {
    // 1. Automatically compiles the local crate to WASM and returns the binary
    let wasm = build_wasm("my-custom-audit");
    
    // 2. Mock the input exactly as the CLI would send it
    let input = WasmInput {
        template: json!({"id": "custom", "name": "Test"}),
        context: HashMap::from([("TARGET_URL".into(), "https://httpbin.org".into())]),
    };
    
    // 3. Execute the WASM inside an Extism sandbox mimicking the engine
    let out = run_plugin(&wasm, &input);
    
    // 4. Assert behavior
    assert!(out.matched);
    assert_eq!(out.findings[0].name, "Custom Vulnerability Found");
}
```

```bash
# Run the test suite for your plugin
cargo test -p my-custom-audit
```

---

## Distributed Architecture

Valayam's engine is designed to scale horizontally across network boundaries.

### gRPC Worker Nodes

You can run a remote worker node serving requests via gRPC, executing WASM plugins completely offloaded from the main CLI.

```bash
# 1. Start the worker node (listens on 50051)
cargo run --bin valayam-worker -- --port 50051

# 2. Delegate scans from the CLI (it will stream the WASM and Context)
cargo run --bin valayam-cli -- -u https://httpbin.org -t ./templates_repo/ --worker http://127.0.0.1:50051
```

## AI Orchestration

Valayam provides native hooks for Python-based autonomous AI orchestration.

```bash
cd services/ai
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export OPENAI_API_KEY="sk-..."

# The agent will dynamically generate templates and route executions to the gRPC worker
python agent.py -u https://example.com -i "Perform a full API audit and test for CORS misconfigurations" --worker localhost:50051
```

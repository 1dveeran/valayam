# Valayam Features & Plugin Ecosystem

Valayam has transitioned from a monolithic architecture with rigid features into a highly extensible, WebAssembly-driven plugin ecosystem. All domain-specific testing logic now runs inside isolated WASM modules powered by `extism`.

This architecture allows developers to rapidly build, test, and deploy new security tests without touching the `valayam-core` crate.

## Official Plugin Ecosystem (`plugins-wasm/`)

The following capabilities are provided as official, standalone WASM plugins compiled from Rust using the `valayam-plugin-sdk`.

### 1. Web & API Security
- **`api-audit`**: Automatically discovers and tests REST API endpoints for common misconfigurations and injection vulnerabilities.
- **`graphql-audit`**: Explores GraphQL endpoints via introspection and mutates queries to test for depth-limiting flaws and unauthorized data access.
- **`cors-audit`**: Actively probes cross-origin configurations to detect overly permissive `Access-Control-Allow-Origin: *` headers or credential leakage.
- **`csp-audit`**: Audits `Content-Security-Policy` headers to detect missing `default-src` directives or unsafe inline executions.
- **`header-scorecard`**: Evaluates targets based on HTTP security headers (e.g., HSTS, X-Frame-Options, Referrer-Policy).
- **`dom-redirect-audit`**: Parses HTML and JS artifacts to locate sinks where user input directly manipulates `location.href` or `window.open`.

### 2. Cloud & Infrastructure Security
- **`cloud-audit`**: Probes for metadata endpoint SSRF vulnerabilities (e.g., AWS IMDSv1/v2, GCP, Azure) to extract IAM credentials.
- **`iac-audit`**: Statically analyzes Terraform, Kubernetes YAML, and Dockerfiles for insecure configurations (e.g., privileged containers, missing network policies).
- **`dependency-audit`**: Parses package lockfiles to identify vulnerabilities by checking them against an offline `vuln-db.sqlite` artifact.

### 3. Specialty Protocols & Architectures
- **`iot-audit`**: Connects to unauthenticated MQTT brokers or fuzzes CoAP packets targeting constrained hardware devices.
- **`mobile-audit`**: Analyzes APK/IPA binaries for hardcoded secrets, insecure TLS, and deep-link manipulations.
- **`browser-audit`**: Manages browser-based testing for dynamic SPA applications.

### 4. Advanced Threat Intel & Recon
- **`recon-audit`**: Automatically maps subdomains and network surfaces.
- **`reputation-audit`**: Compares discovered endpoints against active IP blocklists and threat intelligence feeds.
- **`threat-audit`**: Ingests automated IOCs (Indicators of Compromise) to check against live hosts.
- **`pii-leak-audit`**: Scans application responses for unmasked credit cards, SSNs, or other sensitive information markers.

### 5. Authentication & Identity
- **`oauth-audit`**: Actively tests OAuth authorization code flows for CSRF, open redirects, and token leaks, and evaluates JWT signatures.

## Creating Custom Plugins

Using the `valayam-plugin-sdk`, extending the Valayam engine is as simple as implementing a single `WasmScanner` trait in Rust and compiling to the `wasm32-unknown-unknown` target.

### Example SDK Implementation
```rust
use extism_pdk::*;
use valayam_plugin_sdk::{export_plugin, Finding, WasmInput, WasmOutput, WasmScanner};

pub struct MyCustomAudit;

impl WasmScanner for MyCustomAudit {
    fn execute_scan(input: WasmInput) -> Result<WasmOutput, Error> {
        let mut findings = Vec::new();
        
        // Custom logic here!
        if input.context.contains_key("TARGET_URL") {
            findings.push(Finding {
                id: "custom-finding".into(),
                name: "Custom Match Found".into(),
                severity: "Info".into(),
                extracted_values: None,
            });
        }
        
        Ok(WasmOutput {
            matched: !findings.is_empty(),
            findings,
        })
    }
}

// Wire up the WebAssembly FFI
export_plugin!(MyCustomAudit);
```

### The SDK Architecture
Plugins are provided with access to high-performance, asynchronous networking capabilities executed securely on the host via `extism` host functions:
- `extism_pdk::http::request` - Safely proxy HTTP calls through the core engine's connection pool and rate limiters.
- `valayam-plugin-sdk::host_funcs::dns_resolve` - Utilize the host's DNS resolution stack.
- `valayam-plugin-sdk::host_funcs::kv_get/kv_set` - Persist state locally for multi-step exploits.

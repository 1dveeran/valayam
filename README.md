# Valayam

`valayam` is a high-performance, modular vulnerability scanner core built in Rust. It leverages a modern **Dynamic WASM Plugin Architecture**, decoupling domain-specific scanning logic from the underlying network engine.

## Key Features

- **Extensible WASM Plugin System**: Domain-specific logic is entirely decoupled from the core monolith into secure, sandboxed WebAssembly plugins using the `extism` framework.
- **High-Performance Core Engine**: Built on `tokio` with asynchronous I/O and a global token-bucket rate limiter to prevent self-DoS.
- **Distributed gRPC Architecture**: Run `valayam-worker` daemons across multiple machines and delegate scan execution remotely over gRPC.
- **Network Stealth & Evasion**: Bypasses WAFs and basic TLS fingerprinting via JA3/JA4 spoofing, Proxy rotation, and User-Agent randomization.
- **Enterprise Integrations**: Connects natively to offline SQL databases (e.g., `vuln-db.sqlite`) for local CVE cross-referencing and integrates securely with SIEM pipelines.
- **AI Orchestration**: Provides hooks for external AI agents to autonomously generate templates, coordinate multi-step workflows, and evaluate scan output dynamically.

## Architecture

Valayam is built using a **3-Tiered Vertical Slice Architecture**:
- **Core Platform (`valayam-core`, `valayam-network`)**: Thin shared infrastructure layers providing raw TCP, UDP, DNS, TLS capabilities and stealth enhancements.
- **Dynamic WASM Plugins (`plugins-wasm/`)**: Independent, decoupled modules executing as WebAssembly binaries. Each plugin (e.g., `dependency-audit`, `iot-audit`) provides isolated testing logic.
- **Stateful Interfaces**: The gRPC worker nodes and AI agents drive the core engine, orchestrating execution flows and analyzing the resulting structured metadata.

For a detailed view of the architecture and a data flow diagram, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Usage

Valayam supports running plugins via YAML templates or direct CLI invocation.

```bash
# Local Execution
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo

# Distributed Worker Mode
# 1. Start worker node
cargo run --bin valayam-worker
# 2. Delegate scan from CLI
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo --worker http://127.0.0.1:50051
```

## Plugin Ecosystem

Valayam supports a robust plugin system via its Extism-backed registry. Developers can write their own scanning capabilities using `valayam-plugin-sdk`.

1. **WASM Plugins**: Secure, sandboxed WebAssembly modules capable of utilizing host networking functions. 
2. **gRPC Plugins**: Out-of-process distributed plugins running as separate daemons for heavy, stateful logic.

Manage plugins using the CLI:
```bash
valayam plugin init
valayam plugin generate-key
valayam plugin package
```

## Reporting

The core engine uses an extensible `CompositeReporter` allowing findings to be routed simultaneously to multiple sinks (e.g., `ConsoleReporter`, `JsonReporter`, Webhooks, SIEMs).

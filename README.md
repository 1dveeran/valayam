# Valayam

`valayam` is a high-performance, modular vulnerability scanner core built in Rust. It leverages a modern, async vertical slice architecture where each capability (HTTP, DNS, TCP, TLS) is a self-contained module.

## Key Features

- **Multi-Protocol Scanning**: Native support for HTTP, TCP/UDP connect scanning, DNS auditing, and TLS certificate inspection.
- **Distributed gRPC Architecture**: Run `valayam-worker` daemons across multiple machines and delegate scan execution remotely over gRPC.
- **Embedded Scripting Engine**: Full integration with the Rhai scripting language for complex, multi-step workflows.
- **Network Stealth & Evasion**: Bypasses WAFs and basic TLS fingerprinting via JA3/JA4 spoofing, Proxy rotation, and User-Agent randomization.
- **High-Performance Core**: Built on Tokio with asynchronous I/O and a global token-bucket rate limiter to prevent self-DoS.
- **Dynamic Value Extraction**: Extract values via Regex capture groups and **JSON Pointer paths** (`type: json`), sharing them dynamically across chained requests.
- **Nuclei Compatibility**: Out-of-the-box compatibility with existing HTTP Nuclei templates.
- **AI Orchestration**: Includes a Python-based AI wrapper (`services/ai/`) that leverages LLMs to dynamically generate templates based on natural language objectives, executing them locally or via gRPC worker nodes.

## Architecture

Valayam is built using a **vertical slice architecture**:
- **`core/` & `network/`**: Thin shared infrastructure layers providing raw TCP, UDP, DNS, TLS capabilities and stealth enhancements.
- **`features/`**: Independent, decoupled slices for each capability (`http_scan`, `network_scan`, `dns_audit`, `tls_audit`, `scripting`, `nuclei_compat`). Slices never depend on each other.
- **`template/`**: The central orchestrator that parses YAML schemas and routes execution to the appropriate vertical slices.

## Templates

Valayam templates are written in YAML and organized by protocol in the `templates_repo/` directory:
- `http/`: Standard web vulnerability scanning templates.
- `network/`: TCP/UDP connect and banner-grabbing templates.
- `dns/`: DNS auditing and subdomain takeover templates.
- `tls/`: Certificate expiry and weak cipher checking templates.
- `script/`: Advanced Rhai scripts for complex workflows.

Example usage:
```bash
# Local Execution
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo

# Distributed Worker Mode
# 1. Start worker node
cargo run --bin valayam-worker
# 2. Delegate scan from CLI
cargo run --bin valayam-cli -- -u https://example.com -t ./templates_repo --worker http://127.0.0.1:50051
```

### JSON Extractor Example
You can parse structured JSON responses by using `type: json` with a JSON Pointer (starting with `/`):
```yaml
id: json-api-extract
info:
  name: API Extraction
  severity: High
  compliance:
    owasp: "A01:2021"
requests:
  - method: "GET"
    path: "/api/user"
    extractors:
      - type: "json"
        name: "user_id"
        json: "/data/id"
```

## Roadmap Phases

*   **Phase 1-4:** Core HTTP, Extractors, Rate Limiting, TCP/UDP/DNS scanning.
*   **Phase 5:** Distributed gRPC Architecture and Enterprise Crawler.
*   **Phase 6:** Parameter Fuzzing, TLS auditing, WebSocket built-ins, and WAF Detection.
*   **Phase 10:** Cloud Metadata SSRF Exploitation & Container API Probing.
*   **Phase 11:** Stateful Logic Testing & Automated IDOR Detection.
*   **Phase 12:** Deep WASM Taint Analysis & Local LLM payload generation.

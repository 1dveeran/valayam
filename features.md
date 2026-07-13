# Valayam Features

`valayam` is a high-performance, modular vulnerability scanner core built in Rust. It uses a vertical slice architecture where each capability is a self-contained module with its own parser, executor, and tests.

## Phase 1: High-Performance Core

### 1. HTTP Request Scanning (`features/http_scan/`)
- **Custom Requests**: Full control over methods (GET, POST, PUT, DELETE), paths, headers, and request bodies.
- **Match Types**: Zero-copy regex streaming evaluation against response bodies and HTTP status code matching.
- **Stealth Mode**: Uses `rustls` to safely accept self-signed certificates while bypassing basic TLS fingerprinting via customized user agents.
- **Request Chaining**: Multiple requests within a single template execute sequentially, sharing a variable context for multi-step workflows.

### 2. Dynamic Value Extraction (`features/extractors/`)
- **Regex Capture Groups**: Extract specific values from response bodies or headers using named capture groups.
- **JSON Pointer Extraction**: Extract values from structured JSON API responses using standard JSON Pointer path navigation (RFC 6901, e.g. `/data/token`).
- **CSS Selector Extraction**: Parse HTML response bodies natively to extract element attributes (like `value`, `href`) or inner text (e.g. `input[name=csrf_token]`).
- **Variable Assignment**: Captured values are stored as `{{variable_name}}` and automatically available to all subsequent requests in the same template.
- **Use Cases**: JWT extraction from login responses, CSRF token capture, API key harvesting, session cookie chaining.
- **Configurable Targets**: Extract from `body` or `header` parts of the HTTP response.

### 3. DSL Helper Functions (`features/helpers/`)
- **Encoding**: `{{base64("input")}}`, `{{base64_decode("input")}}`, `{{hex_encode("input")}}`, `{{url_encode("input")}}`, `{{url_decode("input")}}`
- **Hashing**: `{{md5("input")}}`, `{{sha256("input")}}`
- **String Ops**: `{{to_lower("INPUT")}}`, `{{to_upper("input")}}`
- **Composable**: Helpers evaluate after variable substitution, so `{{base64({{username}})}}` works.

### 4. Thread-Safe Rate Limiting (`core/rate_limiter.rs`)
- **Token Bucket Algorithm**: Global RPS limiter using the `governor` crate, shared across all async tasks.
- **CLI Configurable**: `--rate-limit <N>` flag to set max requests per second (default: unlimited).
- **Self-DoS Prevention**: Prevents the scanner from overwhelming target servers or triggering WAF rate limits.

## Phase 2: Multi-Protocol Scanning & Stealth

### 5. TCP/UDP Network Scanning (`features/network_scan/`)
- **Port Discovery**: Concurrent TCP Connect scanning via `tokio::net::TcpStream`.
- **Port Range Syntax**: Supports comma-separated and range syntax (`80,443,8000-8100`).
- **Banner Grabbing**: Reads initial bytes from open TCP connections with configurable timeouts.
- **Banner Matching**: Regex matchers evaluate against captured banners (e.g., detect SSH, FTP, HTTP server versions).
- **UDP Probes**: Basic UDP packet send/receive for service detection on UDP ports.
- **Dynamic Targets**: Host variables (`{{Hostname}}`) are automatically injected.

### 6. DNS Audit Scanning (`features/dns_audit/`)
- **Custom Queries**: Send DNS queries for A, AAAA, CNAME, TXT, and MX records.
- **Response Matching**: Regex matchers evaluate against DNS response records.
- **Subdomain Takeover Detection**: Match CNAME records pointing to unclaimed services (e.g., `*.github.io`, `*.herokuapp.com`).
- **DNS Rebinding Detection**: Identify domains resolving to internal/private IP ranges.

### 7. TLS/SSL Certificate Auditing (`features/tls_audit/`)
- **Certificate Inspection**: Extract issuer, subject, expiry date, SANs, and signature algorithm.
- **Expiry Detection**: Flag certificates that are expired or expiring within a configurable window.
- **Weak Cipher Detection**: Identify servers using deprecated or weak cipher suites.
- **Issuer Matching**: Regex matchers against certificate issuer fields.
- **Self-Signed Detection**: Flag self-signed certificates on public-facing services.

### 8. Evasion & Network Stealth (`stealth/`)
- **JA3/JA4 TLS Fingerprint Spoofing**: Custom `rustls` cipher suite ordering to mimic Chrome and Safari TLS signatures, evading WAF detection.
- **Proxy Rotation**: Automatic cycling through SOCKS5/HTTP proxies loaded from a file (`--proxy-file`).
- **User-Agent Randomization**: Pool of real browser User-Agent strings, randomly selected per request (`--random-agent`).
- **WAF Evasion**: Combined fingerprint spoofing + proxy rotation makes scanner traffic indistinguishable from legitimate browser traffic.

## Phase 3: Scriptability & Complex Exploits

### 9. Embedded Scripting — Rhai Engine (`features/scripting/`)
- **Rhai Integration**: Full integration with the Rhai scripting language for workflows that YAML cannot express.
- **Sandboxing**: Hardened execution with strict limits on CPU cycles (`max_operations`), call stack depth (`max_call_levels`), string size, array size, and map size.
- **HTTP Builtins**: `http_get(url)`, `http_post(url, body)` return structured response maps with status, body, and headers.
- **Regex Builtins**: `regex_match(text, pattern)`, `regex_capture(text, pattern)` for pattern matching and extraction.
- **TCP Builtins**: `tcp_connect(host, port)`, `tcp_send(handle, data)`, `tcp_recv(handle, timeout_ms)` for raw socket scripting.
- **Crypto Builtins**: `base64_encode(text)`, `base64_decode(text)`, `hmac_sha256(key, data)` for API signature computation.
- **Data Builtins**: `json_parse(text)` returns a Rhai Map for structured response parsing.
- **Variable Bridge**: `set_variable(name, value)` and `get_variable(name)` allow scripts to read/write the shared extractor context.
- **Thread Safety**: HTTP client orchestration safely bridges async and sync boundaries across dedicated threads.

### 10. Nuclei Template Compatibility (`features/nuclei_compat/`)
- **Open-Source Compatibility**: Execute standard HTTP Nuclei templates directly (`type: word`, multiple paths, `{{BaseURL}}`).
- **Isolated Architecture**: Nuclei parsing and execution runs in a strictly separated slice, ensuring no architectural pollution of the native engine.
- **Matcher Conditions**: Supports `matchers-condition: and|or` for flexible matching logic.

## Phase 4: High-Performance Concurrency

### 11. Batch Processing & Async I/O
- **Directory Scanning**: Point the CLI at a directory of templates, and the engine concurrently evaluates every template against the target using a `tokio::spawn` task pool.
- **Global Rate Limiting**: All concurrent tasks share a single token-bucket rate limiter to prevent self-DoS.
- **Asynchronous I/O**: Eliminates blocking network calls for maximum throughput.

### 12. Structured Output
- **JSON Serialization**: Full support for logging scan findings to JSON files (via `-o`) for seamless integration into larger data pipelines, SIEMs, or CI/CD dashboards.
- **Extracted Variables**: Scan results include extracted variable values for downstream correlation.

## Phase 5: Distributed Scaling & AI Orchestration

### 13. Distributed Worker Architecture
- **Cargo Workspace**: Engine is extracted as the `valayam-core` library, with `valayam-cli` and `valayam-worker` as separate crates.
- **Worker Daemon**: `valayam-worker` acts as a distributed daemon running in either a synchronous **gRPC server mode** or an asynchronous **TaskBroker queue mode**.
- **Multi-Broker Integration**: Native support for **Redis** (`redis://`) and **RabbitMQ** (`amqp://`) messaging brokers to consume scanning tasks asynchronously and publish findings back, with a structured stub implementation for **Kafka** (`kafka://`).

### 14. AI-Assisted Security & Autonomous Loops
- **Dynamic AI Agent**: A Python AI orchestration layer (`services/ai/`) leveraging LLMs (OpenAI via Pydantic) to dynamically generate and execute Valayam YAML templates based on high-level natural language security objectives.
- **Autonomous Recon Loop**: Rather than single-scan template executions, the agent evaluates previous scan results in a recursive feedback loop to automatically determine follow-up scan targets and templates (up to 5 steps, terminating with a `STOP` command).
- **gRPC Client Integration**: Updates the python `valayam_client.py` to communicate directly with worker daemons over gRPC, bypassing local compilation overheads.

### 15. Enterprise-grade Web Crawler (`features/crawler/`)
- **Asynchronous Crawling Loop**: Scrapes target hosts concurrently while enforcing domain restrictions and matching proxy/rate-limiting constraints.
- **Custom Crawl Headers**: Supports passing auth cookies or token headers (`--crawl-headers`) to scan session-protected applications.
- **OpenAPI scan template compiler**: Automatically parses local or fetched OpenAPI/Swagger JSON specifications and compiles them into Valayam executable requests at runtime.
- **Multi-Format Parsers**:
  - **JavaScript Parser & Parameter Extractor**: Extracts relative routes, query parameters (e.g. `?q=`, `&limit=`), object properties/POST payload keys (like `"username":`), and WebSocket endpoints (`ws://`, `wss://`) from client-side SPA scripts.
  - **WASM Extractor**: Scrapes compiled WebAssembly binary files for hardcoded endpoints.
  - **OpenAPI/Swagger Decoder**: Parses API JSON schemas directly to extract routes and endpoints instantly.
- **Framework Discovery Probes**: Embedded active wordlists to discover Spring Boot Actuator endpoints (like `/actuator/mappings`), J2EE configuration files (`WEB-INF/web.xml`), GraphQL endpoints (`/graphql`), and SOAP services (`?wsdl`).

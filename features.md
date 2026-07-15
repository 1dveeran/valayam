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
- **Banner Grabbing**: Reads initial bytes from open TCP connections with configurable timeouts. Integrates an active **HTTP GET probe fallback** to query version details from silent web services.
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
- **Crypto Builtins**: `base64_encode(text)`, `base64_decode(text)`, `hmac_sha256(key, data)`, `jwt_encode(header, payload, secret)`, and `jwt_decode(token)` for custom token forging and claim inspection.
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

## Phase 6: Offensive Tooling & Active Scanning

### 16. Active Parameter Fuzzing Engine (`features/fuzzer/`)
- **Query Mutation**: Automatically parses existing URL query parameters and injects user-specified payloads (SQL injection, XSS vectors, path traversal) into each parameter position.
- **Targeted Key Selection**: Fuzzes only designated parameter keys or all detected keys when no restriction is set.
- **Anomaly Detection**: Evaluates mutated responses against status code matchers (e.g., 500 for errors) and regex body matchers (e.g., database error strings, reflected payloads).
- **Thread-Safe Execution**: URL mutation logic is isolated from async boundaries to ensure `Send`-safe task spawning.

### 17. SSL/TLS Cipher Suite Auditor (`features/tls_audit/`)
- **Minimum Version Enforcement**: Configurable `min_version` field (e.g. `TLSv1.2`) flags servers negotiating deprecated protocol versions.
- **Version Ranking Engine**: Ranks negotiated TLS versions (TLSv1.0 → TLSv1.3) and compares against policy constraints.
- **Raw ClientHello Probes**: Sends custom SSLv3/TLSv1.0/TLSv1.1 ClientHello handshake bytes to detect legacy protocol support even when modern libraries refuse to negotiate them.
- **Weak Cipher Detection**: Flags CBC, RC4, 3DES, and null cipher suites.

### 18. WebSocket Scripting Builtins (`features/scripting/`)
- **`ws_connect(url)`**: Establishes a WebSocket connection handle as a Rhai Map with inbox queue.
- **`ws_send(handle, msg)`**: Sends a text frame to the WebSocket server.
- **`ws_recv(handle)`**: Reads the next message from the connection's inbox buffer.
- **Mock-Safe Design**: WebSocket builtins use inbox queues enabling deterministic unit testing without external server dependencies.

### 19. WAF Detection & Fingerprinting (`features/waf_detect/`)
- **Header Fingerprinting**: Scans response headers for known WAF signatures (Cloudflare `cf-ray`, Imperva `x-iinfo`, Akamai `x-akamai-transformed`, AWS CloudFront `x-amz-cf-id`, Azure `x-azure-ref`, and more).
- **Body Signature Matching**: Inspects HTML block pages for WAF-specific strings (Cloudflare challenge pages, Incapsula deny pages, ModSecurity error messages, PerimeterX/HUMAN challenges).
- **Active Trigger Probes**: Sends non-destructive XSS/SQLi payloads to provoke WAF blocking responses, then fingerprints the block page.
- **Server Header Analysis**: Identifies CDN/WAF products from the `Server` response header.

## Phase 7: Advanced Post-Exploitation & OOB Testing

### 20. Out-of-Band (OOB) Testing (`features/oob/`)
- **Built-in OOB Server**: Embedded DNS/HTTP server for tracking out-of-band callbacks to detect blind vulnerabilities (e.g., Blind SSRF, Blind SQLi).
- **Correlation Engine**: Generates unique, short-lived correlation IDs to map incoming OOB interactions back to specific scan templates and targets.

### 21. Exploitation Handlers (`features/shells/`)
- **Shell Catchers**: Integrated, interactive bind and reverse shell listeners. Spawns async tasks to manage the TCP stream when a successful remote code execution (RCE) payload is triggered.

## Phase 8: Enterprise Integration, Compliance & Reporting

### 22. Reporting Engine (`valayam-cli/src/reporting/`)
- **HTML & PDF Reports**: Generate standalone, visually appealing reports using a templating engine.
- **Compliance Mapping**: Define framework alignments directly in your templates via the `compliance` dictionary (e.g. `owasp: "A01:2021", cwe: "CWE-89"`). The engine automatically enriches the `ScanResult` JSON logs with these mappings for SIEM integration and reporting to PCI-DSS, MITRE ATT&CK, and OWASP frameworks.

### 23. CI/CD Native Integrations (`.github/workflows/`)
- **Pipeline Integration**: Ready-to-use GitHub Actions (and configurations for GitLab CI/Jenkins) for continuous security scanning in staging environments.

### 24. Real-time Notifications (`valayam-cli/src/notifications.rs`)
- **Webhooks**: Built-in alerting to Slack, Microsoft Teams, and Discord for immediate notification of critical findings.

## Phase 9: Decentralized Scanning & Threat Intelligence

### 25. Peer-to-Peer Worker Network (`valayam-worker/src/broker/p2p.rs`)
- **Decentralized Execution**: Ad-hoc libp2p mesh network to distribute scan tasks across multiple nodes without requiring a centralized broker, effectively bypassing geo-blocks and IP restrictions.

### 26. Threat Intelligence Ingestion (`features/threat_intel/`)
- **Automated Feed Parsing**: Automatically downloads and parses standard Threat Intel feeds (e.g., CISA KEV) to dynamically construct scanning templates for emerging threats.
- **IOC Cross-referencing**: Checks extracted indicators from scans against known malicious databases.

### 27. Anonymity Network Routing (`network/tor.rs`)
- **Native Tor Support**: Routes traffic seamlessly through Tor/I2P proxy chains to enable scanning of `.onion` hidden services while maintaining high operational security.

## Phase 10: Advanced Cloud & Container Security

### 28. Cloud Metadata Exploitation (`features/cloud_sec/`)
- **Automated Metadata Discovery**: Probes for AWS IMDSv1/v2, GCP, and Azure metadata endpoints via SSRF vulnerabilities.
- **Token Harvesting**: Automatically negotiates IMDSv2 challenge-response tokens to extract IAM credentials from vulnerable instances.

### 29. Container Infrastructure Discovery
- **API Targeting**: Automated probing for exposed Docker sockets (`/var/run/docker.sock` over HTTP), Kubernetes API servers, Kubelet endpoints, and etcd instances.
- **Serverless Fuzzing**: Specialized payload mutations targeting AWS Lambda, Azure Functions, and Cloudflare Workers event schemas.

## Phase 11: Stateful Logic & Authorization Testing

### 30. Automated IDOR Detection (`features/auth_logic/`)
- **Cross-Session Replay**: Automatically replays authenticated requests using a secondary, lower-privileged session token to detect Insecure Direct Object References.
- **Resource Ownership Mapping**: Evaluates if secondary sessions can read/write data belonging to the primary session.

### 31. Stateful Flow Fuzzing
- **Transaction Mapping**: Records and replays multi-step transactions (e.g., `AddToCart` -> `Checkout` -> `Pay`).
- **Race Condition Testing**: Floods intermediate transaction states with concurrent requests to identify race conditions and logic bypasses.

### 32. Mass Assignment & Parameter Pollution
- **Extraneous Parameter Injection**: Automatically injects duplicated keys (`?user_id=1&user_id=2`) and privilege-escalation keys (`{"is_admin": true}`) into JSON bodies and query strings.

## Phase 12: Deep Analysis & AI-Driven Evasion

### 33. Local LLM Payload Generator (`features/deep_analysis/`)
- **Dynamic Mutation**: Integrates with local, small-parameter models (e.g., via `llama.cpp`) to dynamically mutate SQLi and XSS payloads in real-time.
- **WAF Learning**: Analyzes WAF block responses to autonomously adjust payloads and bypass filters without external API calls.

### 34. Deep Client-Side Analysis
- **WASM Decompilation**: Automatically decompiles exposed WebAssembly to run local taint analysis for hidden API endpoints and hardcoded secrets.
- **Source Map Recovery**: Reconstructs original TypeScript/JavaScript source code from exposed Source Maps for deep DOM XSS analysis.

### 35. Source Code & Artifact Recovery
- **Backup Scraping**: Automated downloading and parsing of exposed `.git` directories, `.env` files, or backup archives (`backup.zip`) to extract static secrets and configuration parameters.

## Phase 13: Advanced CI/CD & IaC Security

### 36. Infrastructure as Code (IaC) Scanning (`features/iac_audit/`)
- **Static Analysis**: Parse Terraform (`.tf`), Kubernetes YAML, and `Dockerfile` definitions for security misconfigurations (e.g., privileged containers, missing network policies, exposed secrets).
- **Misconfiguration Matchers**: Custom rule engine to evaluate IaC structures without needing to deploy the infrastructure.

### 37. SBOM Generation & Correlation (`features/sbom_audit/`)
- **Dependency Parsing**: Extract dependencies from exposed `package.json`, `Cargo.toml`, `requirements.txt`, or `pom.xml`.
- **Vulnerability Mapping**: Correlate extracted dependencies with known CVEs (using local or external NVD vulnerability databases) to flag vulnerable third-party components.

## Phase 14: API Security & Advanced Protocol Fuzzing

### 38. gRPC & Protobuf Analysis (`features/grpc_audit/`)
- **Service Reflection Probing**: Interrogate gRPC endpoints that have Server Reflection enabled to automatically build request schemas.
- **Protobuf Fuzzing**: Send dynamically mutated protobuf messages to bypass input validation or trigger backend crashes.

### 39. GraphQL Introspection & Mutation Fuzzing (`features/graphql_audit/`)
- **Schema Dumping**: Exploit exposed GraphQL introspection queries to dump the full API schema (types, queries, mutations).
- **Automated Query Generation**: Generate and execute complex nested queries to test for Depth-Limiting vulnerabilities and unauthorized data access.

## Phase 15: Continuous Monitoring & Reconnaissance

### 40. Attack Surface Drift Detection (`features/drift_detect/`)
- **Baseline Comparison**: Store previous scan states (open ports, discovered endpoints, WAF status) and compare them against current scans to alert on infrastructure changes (e.g., newly opened administrative ports).
- **State Storage**: Native integration with SQLite or Redis for state persistence across recurring scans.

### 41. Exposed Credentials Monitoring (`features/cred_monitor/`)
- **Leaked Data Correlation**: Check the target's domain and email addresses against known breach databases (like HaveIBeenPwned API) to flag compromised credentials associated with the target organization.

## Phase 16: Zero-Trust & Identity Security

### 42. OAuth/OIDC Misconfiguration Audit (`features/oauth_audit/`)
- **Flow Exploitation**: Automatically test OAuth authorization code flows for CSRF, open redirects, and implicit flow token leakage.
- **JWT Manipulation**: Forging and manipulating JWT tokens (Algorithm Confusion, "None" algorithm, weak HMAC cracking) to escalate privileges.

### 43. Identity Provider (IdP) Probing (`features/idp_audit/`)
- **SAML Analysis**: Intercept and mutate SAML assertions (XML Signature Wrapping attacks).
- **Directory Discovery**: Active directory enumeration against Azure AD and Okta endpoints.

## Phase 17: Multi-Cloud Post-Exploitation

### 44. AWS IAM Privilege Escalation (`features/aws_escalate/`)
- **Automated Enumeration**: Use harvested AWS keys to enumerate IAM permissions (via `sts:GetCallerIdentity` and `iam:SimulateCustomPolicy`).
- **Lateral Movement**: Test for common privilege escalation vectors (e.g., passing roles to EC2, updating Lambda code).

### 45. Azure & GCP Lateral Movement (`features/azure_gcp_escalate/`)
- **Azure AD Graph Abuse**: Enumerate Azure subscriptions, Service Principals, and exploit excessive directory read permissions.
- **GCP Service Account Hunting**: Pivot through GCP Service Accounts to access Cloud Storage buckets and Compute instances.

## Phase 18: Browser Exploitation & DOM Taint Tracking

### 46. Headless Browser Orchestration (`features/browser_audit/`)
- **Playwright/Puppeteer Integration**: Launch embedded headless browsers to navigate complex SPAs and trigger client-side vulnerabilities.
- **Dynamic DOM XSS**: Automatically inject payloads into input fields and monitor the DOM for execution.

### 47. Advanced Client-Side Taint Tracking
- **Execution Hooking**: Intercept JS function calls (e.g., `eval`, `document.write`, `innerHTML`) within the headless browser to track data flow from sources (URL parameters) to sinks.

## Phase 19: Hardware & IoT Protocol Security

### 48. MQTT & CoAP Fuzzing (`features/iot_audit/`)
- **Broker Probing**: Connect to unauthenticated MQTT brokers and subscribe to wildcard topics (`#`) to intercept sensitive telemetry data.
- **CoAP Payload Fuzzing**: Send malformed Constrained Application Protocol packets to IoT devices to trigger denial of service or remote code execution.

### 49. SCADA/ICS Discovery (`features/scada_audit/`)
- **Modbus/DNP3 Probing**: Safely query industrial control systems on default ports (e.g., TCP 502) to extract PLC configurations and device metadata without disrupting physical operations.

## Phase 20: Autonomous Red Teaming & Auto-Exploitation

### 50. Goal-Oriented AI Planning (`features/auto_redteam/`)
- **Attack Graphs**: Construct dynamic attack graphs mapping the target infrastructure.
- **Autonomous Execution**: The AI agent autonomously chains vulnerabilities (e.g., an SSRF leading to Cloud Metadata exposure leading to AWS Lateral Movement) to achieve a high-level goal defined by the user (e.g., "Extract PII from backend database").

### 51. Persistent Implant Deployment (`features/implant_deploy/`)
- **Automated Rootkits**: Following successful RCE, automatically compile and deploy memory-safe Rust implants to maintain persistence.
- **C2 Integration**: Bridge deployed implants back into Valayam's native OOB correlation engine for centralized command and control.

## Phase 21: Client-Side Security Auditing

### 52. Client-Side API Keys & Secret Leakage Auditing (`features/client_secret_audit/`)
- **Key Harvesting**: Extract hardcoded credentials, API tokens, and AWS secrets from client-side JS bundles.
- **Leakage Matching**: Regex heuristics tuned to catch specific service credentials (e.g. Firebase, Slack, GCP).

### 53. DOM-based Open Redirect Verification (`features/dom_redirect_audit/`)
- **Redirect Parsing**: Locate sinks where user inputs (e.g. `location.href`, `window.open`) are assigned directly from URL query parameters.

## Phase 22: Content Security Policy (CSP) & CORS Auditing

### 54. Dynamic CORS Misconfiguration Testing (`features/cors_audit/`)
- **Origin Reflection**: Query endpoint with randomized Origin headers to detect `Access-Control-Allow-Origin: *` or reflective setups.
- **Credential Checking**: Validate if authenticated CORS requests are permitted from external origins.

### 55. Content Security Policy Bypass Validation (`features/csp_audit/`)
- **Directive Analysis**: Audit `Content-Security-Policy` headers to highlight missing `default-src` or unsafe directives like `unsafe-inline`.

## Phase 23: WAF Rule Validation

### 56. Safe WAF Bypass Probes (`features/waf_bypass_verify/`)
- **Defensive Probing**: Verify WAF resilience by testing non-destructive payload variants (XSS, path traversal) to confirm proper blocking behavior.

### 57. Security Header Scorecard (`features/header_scorecard/`)
- **Header Auditing**: Grade targets based on HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.

## Phase 24: Threat Intelligence & IP Reputation Auditing

### 58. IP Blocklist Validation (`features/reputation_audit/`)
- **Reputation Auditing**: Check target hostnames and IPs against active threat intelligence databases (e.g. Spamhaus, AlienVault).

### 59. Certificate Transparency Log Parsing (`features/ct_log_audit/`)
- **CT Log Monitors**: Query public Certificate Transparency records to map target subdomains.

## Phase 25: Automated Reporting & Remediation Generation

### 60. Markdown Remediation Generator (`features/remediation_gen/`)
- **Fix Suggestions**: Map found CVEs to actionable patch steps, generating markdown vulnerability fix sheets.

### 61. MITRE ATT&CK Matrix Mapping (`features/mitre_mapping/`)
- **Mapping Findings**: Associate each vulnerability finding with a specific MITRE ATT&CK technique code.

## Phase 26: Container & Kubernetes Security Auditing

### 62. Container Image Configuration Auditing (`features/container_audit/`)
- **Dockerfile Analysis**: Parse Dockerfiles and image manifests for known anti-patterns (e.g. running as root, missing health checks, exposed sensitive ports).

### 63. Kubernetes RBAC & Misconfiguration Auditing (`features/k8s_audit/`)
- **Manifest Auditing**: Analyze K8s manifests (YAML) for overly permissive roles, missing network policies, or privileged pods.

## Phase 27: Source Code & Secrets Scanning (SAST)

### 64. Static Code Taint Analysis (`features/sast_taint/`)
- **Source-to-Sink Tracing**: Run fast static analysis over provided source code directories to find direct insecure sinks (e.g. `system()`, `eval()`).

### 65. Hardcoded Secrets Discovery (`features/sast_secrets/`)
- **Entropy & Heuristics**: High-entropy regex scanning across entire repositories to find accidentally committed API keys, passwords, and tokens.

## Phase 28: Network & Port Security

### 66. Subdomain Takeover Validation (`features/subdomain_takeover/`)
- **Dangling CNAMEs**: Verify dangling CNAME DNS records against known cloud provider fingerprints (e.g. GitHub Pages, AWS S3) to prevent hostile domain takeovers.

### 67. Open Port & Service Fingerprinting (`features/port_scan/`)
- **Safe TCP Probing**: Non-intrusive TCP port scanning to identify dangerously exposed administrative services (e.g. SSH, Telnet, raw Database ports).

## Phase 29: API Schema Compliance & Data Privacy

### 68. OpenAPI/Swagger Drift Detection (`features/schema_drift/`)
- **Shadow Endpoint Discovery**: Compare active, discovered API endpoints against the provided formal OpenAPI specification to find undocumented shadow APIs.

### 69. PII Data Exposure Auditing (`features/pii_leak_audit/`)
- **Privacy Scanners**: Monitor HTTP responses for unmasked credit card numbers, SSNs, and other sensitive Personal Identifiable Information markers.

## Phase 30: CI/CD Pipeline & Supply Chain Security

### 70. CI/CD Pipeline Auditing (`features/cicd_audit/`)
- **Workflow Security**: Parse GitHub Actions and GitLab CI YAML configurations to detect script injection vectors (`${{ github.event.issue.body }}`) or exposed secrets.

### 71. Dependency Chain Verification (`features/dependency_audit/`)
- **Lockfile Analysis**: Cross-reference dependency lockfiles (e.g., Cargo.lock, package-lock.json) with known CVEs.
- **Offline VulnDB Integration**: Natively hooks into the offline `vuln-db.sqlite` artifact compiled by the Valayam Platform enterprise ingester to perform lightning-fast local vulnerability checks without triggering rate-limits or requiring active internet connections.

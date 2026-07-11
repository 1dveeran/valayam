# valayam Features

`valayam` is a high-performance, modular vulnerability scanner core built in Rust. It utilizes a declarative YAML syntax to orchestrate network and application layer testing.

## Core Capabilities

### 1. Native HTTP Scanning
- **Custom Requests**: Granular control over methods, paths, and headers.
- **Match Types**: Zero-copy regex streaming evaluation and HTTP status code matching.
- **Stealth Mode**: Uses `rustls` to safely accept self-signed certificates (ideal for internal infrastructure scanning) while bypassing basic TLS fingerprinting via customized user agents.

### 2. TCP Network Scanning
- **Port Discovery**: Concurrent SYN/Connect port scanning via `tokio::net::TcpStream`.
- **Dynamic Targets**: Host variables (`{{Hostname}}`) are automatically injected.

### 3. Embedded Scripting (Multi-Step Workflows)
- **Rhai Engine**: Complete integration with the Rhai scripting language for workflows that YAML cannot express (e.g., token extraction, chaining authenticated requests, math evaluation).
- **Sandboxing**: Hardened execution environment with strict limits on maximum CPU cycles (`max_operations`), call stack depth, and module loading to prevent runaway scripts.
- **Thread Safety**: HTTP client orchestration safely bridges async and sync boundaries across dedicated threads.

### 4. Nuclei Integration (Isolated Architecture)
- **Open-Source Compatibility**: Capable of executing standard HTTP Nuclei templates directly (`type: word`, multiple paths, `{{BaseURL}}`).
- **Isolated Router**: Nuclei parsing and execution happens in a strictly separated module (`src/nuclei/`), ensuring no architectural pollution of the native engine.

### 5. High-Performance Concurrency
- **Batch Processing**: Point the CLI at a directory of templates, and the engine will concurrently evaluate every template against the target using a `tokio::spawn` task pool.
- **Asynchronous I/O**: Eliminates blocking network calls for maximum throughput.

### 6. Structured Output
- **JSON Serialization**: Full support for logging scan findings to JSON files (via `-o`) for seamless integration into larger data pipelines, SIEMs, or CI/CD dashboards.

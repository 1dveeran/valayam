# valayam Architecture

This diagram illustrates the modular architecture of `valayam`, highlighting the strict isolation between Native and Nuclei template execution flows, while still sharing the high-performance network core.

```mermaid
graph TD
    CLI[CLI Parser main.rs] --> Router{Router}
    
    %% Native Flow
    Router -- "-t / --template" --> NativeParser[Native YAML Parser]
    NativeParser --> NativeExec[Native ScanExecutor]
    
    %% Nuclei Flow
    Router -- "-n / --nuclei-template" --> NucleiParser[Nuclei YAML Parser]
    NucleiParser --> NucleiExec[NucleiExecutor]
    
    %% Shared Network Core
    NativeExec --> HTTPCore[StealthHttpClient]
    NativeExec --> TCPCore[tokio::net::TcpStream]
    NucleiExec --> HTTPCore
    
    %% Matchers
    HTTPCore --> Resp[HTTP Response]
    TCPCore --> TCPResp[TCP Connection Status]
    
    Resp --> NativeMatchers[Native Matchers regex/status]
    Resp --> NucleiMatchers[Nuclei Matchers word/status]
    
    %% Scripting (Native Only)
    NativeExec --> ScriptCore[Rhai Script Engine]
    ScriptCore --> Output[JSON Output / Stdout]
    NativeMatchers --> Output
    NucleiMatchers --> Output
    TCPResp --> Output
```

## Component Breakdown

1. **CLI & Router**: The entry point. It parses arguments via `clap`. If `-t` is used, the workflow is routed entirely to the Native stack. If `-n` is used, it's routed to the isolated Nuclei stack.
2. **Parsers**: Native (`VulnerabilityTemplate`) and Nuclei (`NucleiTemplate`) have zero schema overlap.
3. **Executors**: Orchestrate variable substitution (e.g. `{{Hostname}}` for Native, `{{BaseURL}}` for Nuclei).
4. **Shared Network Core**: Both executors rely on the `StealthHttpClient` (a heavily optimized, cert-ignoring wrapper around `reqwest`) for maximum connection throughput.
5. **Matchers**: 
   - Native uses a zero-copy regex streaming evaluator.
   - Nuclei uses a custom fast substring (word) evaluator.
6. **Script Engine**: A sandboxed Rhai instance for complex, multi-step chains (Native templates only).

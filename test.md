# Valayam Testing Guide

Valayam maintains a comprehensive test suite across its cargo workspace architecture, encompassing unit tests for individual modules and integration checks for the AI orchestration layer.

## Rust Workspace Tests

All core logic, parsers, extractors, and protocol modules are tested via standard Cargo unit tests.

### Running All Tests

To run the full test suite across all crates (`valayam-core`, `valayam-cli`, `valayam-worker`):

```bash
cargo test --workspace
```

### Running Specific Crate Tests

```bash
cargo test -p valayam-core
```

### Running Specific Module Tests

To test a specific feature vertical slice (e.g., the scripting engine or HTTP scanner):

```bash
cargo test scripting
cargo test http_scan
cargo test variables
```

### Key Test Coverage Areas

- **Variables & Extractors**: Validates that `{{placeholders}}` are correctly parsed, substituted, and that regex, JSON Pointer, and CSS extractors appropriately populate the shared variable context.
- **DSL Helpers**: Unit tests ensure `base64`, `md5`, `sha256`, `url_encode`, and string manipulation functions correctly transform data.
- **Template Schemas**: Tests serialization and deserialization of YAML templates (both native and Nuclei compatibility modes).
- **Rate Limiting**: Verifies the token-bucket algorithm properly throttles requests without deadlocking.
- **Scripting Engine**: Confirms Rhai sandboxing constraints (limits on operations, infinite loops) and execution of built-in functions.
- **Web Crawler Parsers**: Validates Javascript regex parsers, WASM binary strings extraction, and OpenAPI schema routes compilation.

## Python AI Layer Tests

The AI Agent orchestration layer interacts with the Rust CLI via subprocesses.

### Running the AI Agent Test

You can perform a dry-run/local test of the AI integration by running the Python agent without an active OpenAI API key. It will fall back to a default HTTP scan template and execute it against the target.

```bash
cd services/ai
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1
# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt

# Run the local fallback test (Subprocess Mode)
python agent.py -u https://httpbin.org -i "Check if the target is alive"

# Run the local fallback test (gRPC Mode - requires valayam-worker running)
python agent.py -u https://httpbin.org -i "Check if the target is alive" --worker localhost:50051
```

Expected output is a JSON finding proving that the Python script successfully generated a template, launched the scan (locally or via worker), captured the results, and successfully parsed the findings.

# Contributing to Valayam

First off, thank you for considering contributing to Valayam! It's people like you that make Valayam such a great tool for the community.

## 1. Where do I go from here?

If you've noticed a bug or have a feature request, make one! It's generally best if you get confirmation of your bug or approval for your feature request this way before starting to code.

## 2. Setting up your environment

Valayam is built in Rust and makes heavy use of WebAssembly (via Extism).

1. **Install Rust**: If you haven't already, install Rust using [rustup](https://rustup.rs/).
2. **Install the WebAssembly target**:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```
3. **Build the Core Engine**:
   ```bash
   cargo build
   ```

## 3. Developing a WASM Plugin

Valayam's architecture separates the core engine from the vulnerability scanning logic. All scanning logic lives in `plugins-wasm/`.

To create a new plugin:
1. Copy an existing plugin (like `plugins-wasm/api-audit`) to a new folder in `plugins-wasm/`.
2. Update the `Cargo.toml` name.
3. Implement the `WasmScanner` trait from `valayam-plugin-sdk`.
4. Add your plugin to the root `Cargo.toml` workspace members list.

### Testing your Plugin

We provide a dedicated `test-runner` for testing WASM plugins locally without booting the full engine.

```bash
cargo test -p my-new-plugin
```

## 4. Code Style

- We enforce standard Rust formatting. Please run `cargo fmt` before committing.
- We enforce clippy lints. Please run `cargo clippy -- -D warnings` before committing to ensure there are no warnings.

## 5. Submitting a Pull Request

1. Fork the repository and create a new branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes (`cargo test`).
4. Ensure your code passes `cargo fmt` and `cargo clippy`.
5. Issue that pull request!

# Valayam Plugin Development Guide

Valayam supports plugins in any language using **WASM** or **gRPC** backends. To simplify plugin distribution, Valayam uses the **Valayam Plugin Archive (`.vpa`)** standard.

## 1. The Valayam Plugin Archive (`.vpa`)

A `.vpa` file is a ZIP archive containing a `plugin.yaml` manifest and your plugin code/executables. The engine automatically extracts and runs the entrypoint specified in the manifest.

### `plugin.yaml` Specification

```yaml
name: "valayam-advanced-sqli"
version: "1.0.0"
author: "SecurityTeam"
runtime: "grpc" # Can be "grpc" or "wasm"
language: "python"
entrypoint: "run.bat" # The executable/script to run
capabilities:
  - "network_scan"
```

## 2. Developing with the Python SDK

We provide the `valayam-sdk` for Python to eliminate boilerplate. 

### Installation
```bash
pip install valayam-sdk
```

### Quickstart

The easiest way to start is by using the CLI to scaffold a new plugin:

```bash
valayam plugin init my-custom-scanner --lang python --runtime grpc
```

This will automatically create a new directory with `plugin.py`, `plugin.yaml`, `requirements.txt`, and `run.bat` (all the boilerplate you need!).

### Example: Custom Scanner Plugin

If you chose python, your `plugin.py` will look like this:

```python
from valayam_sdk import PluginServer, ScannerPlugin, Finding

class AdvancedSQLiScanner(ScannerPlugin):
    def execute(self, template, context):
        target = context.get("target_url", "")
        # Run custom security checks here...
        
        return [
            Finding(title="SQL Injection Detected", severity="CRITICAL", description=f"Found SQLi in {target}")
        ]

if __name__ == "__main__":
    PluginServer(AdvancedSQLiScanner()).serve()
```

### Packaging your Python Plugin

For Python, you usually want to bundle a virtual environment or rely on the host's Python. A robust way is to use a `.bat` or `.sh` wrapper as your `entrypoint`.

Create `run.bat`:
```bat
@echo off
python plugin.py
```

Create `plugin.yaml`:
```yaml
name: "advanced-sqli-python"
version: "1.0.0"
runtime: "grpc"
language: "python"
entrypoint: "run.bat"
```

Then package it using the Valayam CLI:
```bash
valayam plugin package ./my-plugin-dir --output advanced-sqli-python.vpa
```

Drop `advanced-sqli-python.vpa` into your `plugins/` directory, and Valayam will automatically load it!

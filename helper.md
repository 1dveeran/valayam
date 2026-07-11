# valayam Helper

This document provides examples on how to use the `valayam` scanner.

## Getting Help

The scanner is built with a standard command-line interface. You can view all available commands, flags, and options by using the `--help` or `-h` flag.

```bash
cargo run -- --help
```

## Running Scans

Scans are initiated by providing a target and a template.

### Basic HTTP Scan

This runs the default `demo-template.yaml` against the default target (`https://httpbin.org`). The template first checks for a reflected parameter in an HTTP response body and then performs a quick port scan.

```bash
cargo run
```

### Targeting a different URL

Use the `-u` or `--target` flag.

```bash
cargo run -- --target https://example.com
```

### Using a specific template or directory

Use the `-t` or `--template` flag to provide a path to a custom YAML template file, or a directory containing multiple `.yaml` files.

```bash
# Single template
cargo run -- -t ./templates_repo/test1.yaml

# Batch execution (runs all templates in the directory concurrently)
cargo run -- -t ./templates_repo/
```

### Saving results to a file

Use the `-o` or `--output` flag to save findings to a JSON file. Each finding will be appended as a new line.

```bash
cargo run -- -t ./templates_repo/ -o results.json
```

## Example Templates

### HTTP-Only Template

Create a file `http-only.yaml`:
```yaml
id: http-only-example
info:
  name: "HTTP Only Example"
  severity: "Info"
requests:
  - method: "GET"
    path: "/"
    matchers:
      - type: "status"
        part: "status"
        status:
          - 200
```
Run it:
```bash
cargo run -- -t http-only.yaml
```

### Network-Only Template

Create a file `network-only.yaml`:
```yaml
id: network-only-example
info:
  name: "Network Only Example"
  severity: "Info"
network:
  - host: "{{Hostname}}"
    ports:
      - "80"
      - "443"
```
Run it:
```bash
cargo run -- -t network-only.yaml --target example.com
```

### Script-Based Template (Rhai)

Create a file `script-only.yaml`:
```yaml
id: script-example
info:
  name: "Script Example"
  severity: "High"
scripts:
  - engine: "rhai"
    source:
      code: |
        let resp = http_get(target_url + "/login");
        if resp.status == 200 {
            let has_error = regex_match(resp.body, "invalid syntax");
            return has_error;
        }
        return false;
```
Run it:
```bash
cargo run -- -t script-only.yaml
```

### Nuclei Template (Compatibility Mode)

To run external Nuclei templates, you must use the `-n` or `--nuclei-template` flag instead of `-t`. This ensures the engine uses the isolated Nuclei parsing and execution module.

Create a file `nuclei-demo.yaml`:
```yaml
id: nuclei-example
info:
  name: Nuclei Info Disclosure
  author: valayam
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.env"
    matchers:
      - type: word
        words:
          - "[core]"
          - "DB_PASSWORD"
```
Run it:
```bash
cargo run -- -n nuclei-demo.yaml --target https://example.com
```

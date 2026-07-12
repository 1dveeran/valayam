# Valayam Helper

This document provides examples on how to use the `valayam` scanner, covering all template types and features.

## Getting Help

```bash
cargo run -- --help
```

## CLI Flags

| Flag | Short | Description |
|---|---|---|
| `--target` | `-u` | Target Base URL (default: `https://httpbin.org`) |
| `--template` | `-t` | Path to Native YAML template file or directory |
| `--nuclei-template` | `-n` | Path to Nuclei YAML template file or directory |
| `--output` | `-o` | Path to write JSON output to |
| `--rate-limit` | `-r` | Max requests per second (default: unlimited) |
| `--proxy-file` | | Path to proxy list file (one per line) |
| `--random-agent` | | Randomize User-Agent per request |

## Running Scans

### Basic HTTP Scan

```bash
# Uses default demo template against default target (httpbin.org)
cargo run

# Custom target
cargo run -- -u https://example.com -t ./templates_repo/demo-template.yaml

# Batch execution (all .yaml files in directory, concurrently)
cargo run -- -u https://example.com -t ./templates_repo/

# Save findings to JSON
cargo run -- -t ./templates_repo/ -o results.json

# Rate-limited scan (max 5 requests/second)
cargo run -- -t ./templates_repo/ --rate-limit 5
```

---

## Template Examples

### HTTP-Only Template

Basic HTTP request with regex and status code matching.

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

```bash
cargo run -- -t http-only.yaml
```

---

### Extractors — Chained Authentication Flow

Extract a token from the login response and use it in a subsequent API request. The `extractors` field captures regex groups into named variables that are available via `{{variable_name}}` in later requests.

```yaml
id: auth-chain-extractor
info:
  name: "Authenticated API Check"
  severity: "High"
  description: "Logs in, extracts a bearer token, and queries a protected endpoint."
requests:
  # Step 1: Login and extract the token
  - method: "POST"
    path: "/api/login"
    body: "username=admin&password=admin"
    headers:
      Content-Type: "application/x-www-form-urlencoded"
    matchers:
      - type: "status"
        part: "status"
        status:
          - 200
    extractors:
      - type: "regex"
        name: "auth_token"
        part: "body"
        regex: '"token":\s*"([^"]+)"'
        group: 1

  # Step 2: Use the extracted token in a protected request
  - method: "GET"
    path: "/api/admin/users"
    headers:
      Authorization: "Bearer {{auth_token}}"
    matchers:
      - type: "status"
        part: "status"
        status:
          - 200
      - type: "regex"
        part: "body"
        regex:
          - '"role":\s*"admin"'
```

```bash
cargo run -- -t auth-chain.yaml -u https://vulnerable-app.com
```

---

### Extractors — CSRF Token Extraction

Extract a CSRF token from a form page and use it in a POST request.

```yaml
id: csrf-token-chain
info:
  name: "CSRF Token Bypass Check"
  severity: "Medium"
requests:
  - method: "GET"
    path: "/form"
    matchers:
      - type: "status"
        part: "status"
        status: [200]
    extractors:
      - type: "regex"
        name: "csrf"
        part: "body"
        regex: 'name="csrf_token"\s+value="([^"]+)"'
        group: 1

  - method: "POST"
    path: "/submit"
    body: "csrf_token={{csrf}}&action=delete_account"
    headers:
      Content-Type: "application/x-www-form-urlencoded"
    matchers:
      - type: "status"
        part: "status"
        status: [200]
```

---

### DSL Helper Functions

Use built-in helper functions for encoding, hashing, and transformations directly in template values.

```yaml
id: helper-functions-demo
info:
  name: "DSL Helper Demo"
  severity: "Info"
requests:
  # Base64-encoded Basic Auth header
  - method: "GET"
    path: "/api/protected"
    headers:
      Authorization: "Basic {{base64(admin:admin)}}"
    matchers:
      - type: "status"
        part: "status"
        status: [200]

  # MD5 hash check
  - method: "GET"
    path: "/api/checksum?hash={{md5(test_payload)}}"
    matchers:
      - type: "regex"
        part: "body"
        regex:
          - '"valid":\s*true'

  # URL-encoded payload
  - method: "GET"
    path: "/search?q={{url_encode(<script>alert(1)</script>)}}"
    matchers:
      - type: "regex"
        part: "body"
        regex:
          - "<script>alert\\(1\\)</script>"
```

**Available helpers:**

| Helper | Description | Example |
|---|---|---|
| `base64(input)` | Base64 encode | `{{base64(admin:password)}}` |
| `base64_decode(input)` | Base64 decode | `{{base64_decode(YWRtaW4=)}}` |
| `url_encode(input)` | Percent-encode | `{{url_encode(a b&c)}}` |
| `url_decode(input)` | Percent-decode | `{{url_decode(a%20b)}}` |
| `md5(input)` | MD5 hex digest | `{{md5(hello)}}` |
| `sha256(input)` | SHA-256 hex digest | `{{sha256(hello)}}` |
| `hex_encode(input)` | Raw hex encoding | `{{hex_encode(ABC)}}` |
| `to_lower(input)` | Lowercase | `{{to_lower(HELLO)}}` |
| `to_upper(input)` | Uppercase | `{{to_upper(hello)}}` |

---

### Network Scanning — TCP with Banner Grabbing

Scan ports and match against service banners.

```yaml
id: network-banner-grab
info:
  name: "SSH and FTP Banner Detection"
  severity: "Info"
network:
  - host: "{{Hostname}}"
    ports:
      - "21-22"
      - "80"
      - "443"
      - "8080-8100"
    banner_timeout_ms: 3000
    matchers:
      - type: "regex"
        part: "banner"
        regex:
          - "SSH-2\\.0-OpenSSH"
          - "220.*FTP"
          - "Apache Tomcat"
```

```bash
cargo run -- -t network-banner.yaml -u example.com
```

---

### Network Scanning — Port Discovery Only

Simple open port detection without banner matching.

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
      - "3306"
      - "5432"
      - "6379"
      - "27017"
```

```bash
cargo run -- -t network-only.yaml -u example.com
```

---

### DNS Audit — Subdomain Takeover Detection

Query DNS records and match for takeover indicators.

```yaml
id: dns-subdomain-takeover
info:
  name: "Subdomain Takeover Check"
  severity: "High"
  description: "Detects CNAME records pointing to unclaimed services."
dns:
  - domain: "{{Hostname}}"
    query_type: "CNAME"
    matchers:
      - type: "regex"
        regex:
          - "\\.github\\.io$"
          - "\\.herokuapp\\.com$"
          - "\\.azurewebsites\\.net$"
          - "\\.cloudfront\\.net$"
```

```bash
cargo run -- -t dns-takeover.yaml -u sub.example.com
```

---

### DNS Audit — TXT Record Inspection

Check for SPF, DKIM, and DMARC misconfigurations.

```yaml
id: dns-txt-audit
info:
  name: "DNS TXT Record Audit"
  severity: "Medium"
dns:
  - domain: "{{Hostname}}"
    query_type: "TXT"
    matchers:
      - type: "regex"
        regex:
          - "v=spf1.*\\+all"    # Overly permissive SPF
```

---

### TLS/SSL Certificate Audit

Inspect TLS certificates for expiry, weak ciphers, and issuer details.

```yaml
id: tls-cert-audit
info:
  name: "TLS Certificate Weakness Check"
  severity: "Medium"
  description: "Checks for expired certs, weak ciphers, and self-signed certificates."
tls:
  - host: "{{Hostname}}"
    port: 443
    matchers:
      - type: "expired"
      - type: "weak_cipher"
      - type: "self_signed"
```

```yaml
# TLS issuer matching
id: tls-issuer-check
info:
  name: "TLS Issuer Audit"
  severity: "Info"
tls:
  - host: "{{Hostname}}"
    port: 443
    matchers:
      - type: "regex"
        part: "issuer"
        regex:
          - "Let's Encrypt"
```

```bash
cargo run -- -t tls-audit.yaml -u https://example.com
```

---

### Rhai Script — Multi-Step Workflow

Use embedded Rhai scripting for complex logic that YAML cannot express.

```yaml
id: script-multi-step-demo
info:
  name: "Multi-Step Script Demo"
  severity: "Info"
  description: "Demonstrates Rhai scripting for chained HTTP requests."
scripts:
  - engine: "rhai"
    source:
      code: |
        // Step 1: Make an initial request and verify it succeeds
        let resp = http_get(target_url + "/get?step=1&marker=valayam_script");
        log("Step 1 status: " + resp.status);

        if resp.status != 200 {
          return false;
        }

        // Step 2: Extract a value from the response using regex
        let has_marker = regex_match(resp.body, "valayam_script");
        log("Step 1 marker found: " + has_marker);

        if !has_marker {
          return false;
        }

        // Step 3: Chain a second request using data from step 1
        let resp2 = http_get(target_url + "/get?step=2&ref=chained_from_step1");
        log("Step 2 status: " + resp2.status);

        // Final verdict: both requests must succeed
        resp2.status == 200
```

```bash
cargo run -- -t script-demo.yaml
```

---

### Rhai Script — Advanced Features

Using TCP builtins, crypto functions, and variable bridge.

```yaml
id: script-advanced-demo
info:
  name: "Advanced Script Demo"
  severity: "High"
scripts:
  - engine: "rhai"
    source:
      code: |
        // TCP banner grab
        let conn = tcp_connect(hostname, 22);
        let banner = tcp_recv(conn, 5000);
        log("SSH Banner: " + banner);

        // Compute API signature
        let timestamp = "1720000000";
        let signature = hmac_sha256("secret_key", "GET/api/data" + timestamp);
        log("Computed HMAC: " + signature);

        // Parse JSON response
        let resp = http_get(target_url + "/api/info");
        let data = json_parse(resp.body);
        log("Server version: " + data.version);

        // Write extracted values to shared context
        set_variable("server_version", data.version);

        data.version != "patched"
```

---

### Rhai Script — External File

Load script source from a separate `.rhai` file for complex exploits.

```yaml
id: script-from-file
info:
  name: "External Script Example"
  severity: "High"
scripts:
  - engine: "rhai"
    source:
      path: "./scripts/custom_exploit.rhai"
```

```bash
cargo run -- -t script-file.yaml -u https://target.com
```

---

### Mixed Template — All Features Combined

A single template can use HTTP requests, extractors, helpers, network scanning, DNS audit, TLS audit, and scripts together. The engine executes them in order: HTTP → Network → DNS → TLS → Scripts.

```yaml
id: full-feature-demo
info:
  name: "Full Feature Demonstration"
  severity: "Critical"
  description: "Demonstrates all Valayam capabilities in a single template."

requests:
  - method: "POST"
    path: "/api/auth"
    body: "user={{base64(admin)}}&pass={{md5(password123)}}"
    headers:
      Content-Type: "application/x-www-form-urlencoded"
    matchers:
      - type: "status"
        part: "status"
        status: [200]
    extractors:
      - type: "regex"
        name: "session_id"
        part: "header"
        regex: 'Set-Cookie:\s*session=([^;]+)'
        group: 1

  - method: "GET"
    path: "/api/admin"
    headers:
      Cookie: "session={{session_id}}"
    matchers:
      - type: "regex"
        part: "body"
        regex:
          - '"admin":\s*true'

network:
  - host: "{{Hostname}}"
    ports:
      - "3306"
      - "5432"
      - "6379"
    banner_timeout_ms: 2000
    matchers:
      - type: "regex"
        part: "banner"
        regex:
          - "mysql|MariaDB|PostgreSQL|Redis"

dns:
  - domain: "{{Hostname}}"
    query_type: "CNAME"
    matchers:
      - type: "regex"
        regex:
          - "\\.github\\.io$"

tls:
  - host: "{{Hostname}}"
    port: 443
    matchers:
      - type: "expired"

scripts:
  - engine: "rhai"
    source:
      code: |
        let session = get_variable("session_id");
        log("Using extracted session: " + session);
        let resp = http_get(target_url + "/api/secrets");
        resp.status == 200
```

---

### Nuclei Template (Compatibility Mode)

Use the `-n` flag for Nuclei templates. This routes to the isolated Nuclei execution engine.

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
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "[core]"
          - "DB_PASSWORD"
      - type: status
        status:
          - 200
```

```bash
cargo run -- -n nuclei-demo.yaml -u https://example.com
```

---

## Stealth Options

### Proxy Rotation

Create a proxy file (`proxies.txt`), one proxy per line:
```
socks5://127.0.0.1:9050
http://proxy1.example.com:8080
socks5://proxy2.example.com:1080
```

```bash
cargo run -- -t ./templates_repo/ --proxy-file proxies.txt
```

### Random User-Agent

```bash
cargo run -- -t ./templates_repo/ --random-agent
```

### Combined Stealth + Rate Limiting

```bash
cargo run -- -t ./templates_repo/ -u https://target.com \
  --rate-limit 3 --proxy-file proxies.txt --random-agent \
  -o results.json
```

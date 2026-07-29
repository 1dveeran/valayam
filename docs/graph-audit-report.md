# Graph Audit Report — Isolated Nodes & Architecture Gaps

**Date:** 2026-07-29  
**Source:** `graphify-out/GRAPH_REPORT.md` (generated 2026-07-26)  
**Graph Stats:** 2960 nodes · 4192 edges · 750 communities (166 shown, 584 thin omitted)  
**Extraction Quality:** 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS

---

## Isolated Nodes (33 found)

Nodes with ≤1 connection — possible missing edges or dead code.

### Already Remediated

| Node | Status | Action Taken |
|------|--------|-------------|
| `MycustomscannerScanner` | ✅ Cleaned | `my-custom-scanner/` directory deleted (P4.5) |
| `SafePluginFuture<F>` | ✅ Documented | Module-level docs in `unwind_safe.rs` (P4.6) |

### Expected / Low-Risk (Template Section Types)

These are thin marker types implementing `TemplateSection` trait. They're deliberately small — the trait provides the interface, the types just tag sections.

- `AuthTemplate`, `AutoRedteamTemplate`, `AzureGcpEscalateTemplate`
- `AwsEscalateTemplate`, `BrowserAuditTemplate`, `CicdAuditTemplate`
- `ClientSecretAuditTemplate`, `CorsAuditTemplate`, `IotAuditTemplate`
- `PortScanTemplate`, `TlsAuditTemplate`

**Verdict:** No action needed. These are schema-contract types whose behavior is in the trait, not in themselves.

### Inferred-Only Nodes (Possible False Positives)

These only appear in INFERRED edges (confidence 0.79 avg). They may be LLM-hallucinated relationships:

- `api_auth_logic_dispatch()`, `api_cred_monitor()`
- `spec_scada()`, `spec_scripting()`
- `scan_attack_graph()`, `scan_auto_exploit()`

**Verdict:** These need manual verification. If the relationships are real, add explicit imports/references. If not, the inferred edges are harmless noise.

### True Isolated (Warrants Investigation)

| Node | Location | Risk | Recommendation |
|------|----------|------|----------------|
| `FeedIngestor` | Unknown | Low | Check if this is dead code or planned feature. If unused, remove or add TODO. |
| `TorRouter` | `crates/valayam-network/src/network/tor.rs` | Low | Exists as `pub mod tor;` in network module. Check if integrated. |
| `PluginPublisher` / `PluginPuller` | `crates/valayam-engine/src/` | Low | OCI registry push/pull — functional but only triggered via CLI, not connected in orchestration graph. |

---

## Import Cycles

**None detected.** ✅

---

## Community Cohesion Concerns

| Community | Cohesion | Nodes | Assessment |
|-----------|----------|-------|------------|
| Community 0 | 0.06 | 51 | Scan orchestration hub — low cohesion expected (central coordinator) |
| Community 2 | 0.07 | 53 | Template types — fine, they're schema types |
| Community 3 | 0.06 | 21 | Core plugins — medium cohesion, expected for dispatcher pattern |
| Community 91 | 0.67 | 6 | `execute_template()` — tightly coupled execution core ✅ |

**Verdict:** Low-cohesion communities are concentrated in orchestrator/dispatcher roles where some heterogeneity is expected. No structural issues.

---

## Inferred Edge Verification

103 inferred edges (2% of total, avg confidence 0.79). Two hotspots:

1. **`run_plugin()` (46 inferred edges):** Connections to `api_auth_logic_dispatch()`, `api_cred_monitor()`, etc. — these are test/dispatch functions that call `run_plugin()` indirectly. **Plausible.**
2. **`build_wasm()` (46 inferred edges):** Same test functions — tests build WASM plugins then run them. **Plausible.**

**Verdict:** Inferred edges are reasonable. No action needed.

---

## Summary

| Category | Count | Verdict |
|----------|-------|---------|
| Already cleaned | 2 | ✅ P4.5, P4.6 |
| Template types (expected) | 11 | ✅ No action |
| Inferred-only (verify) | ~5 | ⚠️ Manual check |
| True isolated | 3 | 🔍 Investigate `FeedIngestor`, `TorRouter`, `PluginPublisher/Puller` |
| Import cycles | 0 | ✅ Clean |
| **Net actionable** | **~8** | **Low priority — no structural issues found** |
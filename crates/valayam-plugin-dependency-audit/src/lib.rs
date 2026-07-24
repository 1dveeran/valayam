// TODO: Implement Dependency Chain Verification (Phase 30).
// - Lockfile analysis (Cargo.lock, package-lock.json) for known CVEs.
// - Native hook into the offline `vuln-db.sqlite` artifact for fast local checks.
// - Map transitive dependency vulnerabilities back to the root package.

pub mod executor;
pub mod extractor;
pub mod vuln_db;


use valayam_engine::impl_scan_plugin;
use valayam_engine::traits::PluginOutcome;

impl_scan_plugin!(DependencyAuditPlugin, "dependency_audit", dependency_audit,
    |ctx, template, finding_tx| {
        if let Some(res) = executor::execute(
            &template.dependency_audit, &template.id, &template.info,
        ).await {
            let _ = finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
);

use std::io::Cursor;
use rusty_axml::{parse_from_reader, find_nodes_by_type, is_component_exposed};

pub struct ManifestAnalyzer;

impl ManifestAnalyzer {
    pub fn analyze_apk_manifest(binary_data: &[u8]) -> Result<Vec<String>, String> {
        let mut findings = Vec::new();

        let cursor = Cursor::new(binary_data);
        let axml = parse_from_reader(cursor).map_err(|e| format!("Failed to parse AXML: {:?}", e))?;
        
        let activities = find_nodes_by_type(&axml, "activity");
        let services = find_nodes_by_type(&axml, "service");
        let receivers = find_nodes_by_type(&axml, "receiver");

        let mut all_components = activities;
        all_components.extend(services);
        all_components.extend(receivers);

        for component in all_components {
            if is_component_exposed(&component) {
                let name = component.borrow().get_attr("android:name").unwrap_or("Unknown").to_string();
                let c_type = component.borrow().element_type().to_string();
                findings.push(format!("Insecure IPC: {} '{}' is exposed (exported=true or implicit intents). Verify if this is intended.", c_type, name));
            }
        }

        Ok(findings)
    }

    pub fn analyze_ipa_plist(plist_data: &[u8]) -> Result<Vec<String>, String> {
        let mut findings = Vec::new();
        
        // Very basic string parsing for Info.plist to find NSAppTransportSecurity
        let content = String::from_utf8_lossy(plist_data);
        if content.contains("<key>NSAllowsArbitraryLoads</key>") {
            // Simplified check, in reality we'd parse the XML/binary plist
            if let Some(idx) = content.find("<key>NSAllowsArbitraryLoads</key>") {
                let remainder = &content[idx..];
                if remainder.contains("<true/>") {
                    findings.push("Insecure NSAppTransportSecurity: NSAllowsArbitraryLoads is set to true.".to_string());
                }
            }
        }

        Ok(findings)
    }
}

use super::graph::{AttackGraph, NodeData, NodeType, EdgeData, EdgeType};
use crate::core::result::ScanResult;
use url::Url;

impl AttackGraph {
    /// Ingest a ScanResult and add corresponding nodes and edges to the graph.
    pub fn ingest_result(&mut self, result: &ScanResult) {
        // Example logic: Create a node for the target domain/IP
        let target_node_id = result.target.clone();
        
        let target_type = if Url::parse(&target_node_id).is_ok() {
            NodeType::Domain
        } else {
            NodeType::IpAddress
        };

        let target_idx = self.add_node(NodeData {
            id: target_node_id.clone(),
            label: target_node_id.clone(),
            node_type: target_type,
            severity: None,
        });

        // Create a node for the vulnerability
        let vuln_node_id = format!("{}-{}", target_node_id, result.template_id);
        let vuln_idx = self.add_node(NodeData {
            id: vuln_node_id.clone(),
            label: result.template_name.clone(),
            node_type: NodeType::Vulnerability,
            severity: Some(result.template_severity.clone()),
        });

        // Add an edge: Domain -> HasVulnerability -> Vulnerability
        self.add_edge(&target_node_id, &vuln_node_id, EdgeData {
            edge_type: EdgeType::HasVulnerability,
            description: None,
        });
        
        // Example: if the payload contains credentials, link it as ExposesSecret
        if result.payload.contains("password=") || result.payload.contains("secret=") {
            let secret_id = format!("{}-secret", vuln_node_id);
            self.add_node(NodeData {
                id: secret_id.clone(),
                label: "Exposed Secret".to_string(),
                node_type: NodeType::Secret,
                severity: Some("Critical".to_string()),
            });
            self.add_edge(&vuln_node_id, &secret_id, EdgeData {
                edge_type: EdgeType::ExposesSecret,
                description: Some("Leaked via payload".to_string()),
            });
        }
    }
}

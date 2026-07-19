#[cfg(test)]
mod tests {
    use crate::features::attack_graph::graph::{AttackGraph, NodeData, NodeType, EdgeData, EdgeType};

    #[test]
    fn test_graph_building_and_pathfinding() {
        let mut graph = AttackGraph::new();

        // 1. Add Entry Node (Domain)
        graph.add_node(NodeData {
            id: "example.com".to_string(),
            label: "example.com".to_string(),
            node_type: NodeType::Domain,
            severity: None,
        });

        // 2. Add Target Node (Secret)
        graph.add_node(NodeData {
            id: "aws-secret-key".to_string(),
            label: "AWS Secret Key".to_string(),
            node_type: NodeType::Secret,
            severity: Some("Critical".to_string()),
        });

        // 3. Add Intermediate Node (Vulnerability)
        graph.add_node(NodeData {
            id: "cve-2024-1234".to_string(),
            label: "RCE Vulnerability".to_string(),
            node_type: NodeType::Vulnerability,
            severity: Some("High".to_string()),
        });

        // Connect them: Domain -> Vulnerability -> Secret
        graph.add_edge("example.com", "cve-2024-1234", EdgeData {
            edge_type: EdgeType::HasVulnerability,
            description: None,
        });

        graph.add_edge("cve-2024-1234", "aws-secret-key", EdgeData {
            edge_type: EdgeType::ExposesSecret,
            description: None,
        });

        // Find Kill Chain
        let path = graph.find_kill_chain("example.com", "aws-secret-key");
        assert!(path.is_some());
        
        let path_nodes = path.unwrap();
        assert_eq!(path_nodes.len(), 3);
        assert_eq!(path_nodes[0], "example.com");
        assert_eq!(path_nodes[1], "cve-2024-1234");
        assert_eq!(path_nodes[2], "aws-secret-key");
    }
}

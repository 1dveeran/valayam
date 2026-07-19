use petgraph::graph::{NodeIndex, DiGraph};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NodeType {
    Domain,
    IpAddress,
    Port,
    Vulnerability,
    Secret,
    User,
    CloudAsset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeData {
    pub id: String,
    pub label: String,
    pub node_type: NodeType,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    ResolvesTo,
    HasPort,
    HasVulnerability,
    ExposesSecret,
    GrantsAccessTo,
    Contains,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeData {
    pub edge_type: EdgeType,
    pub description: Option<String>,
}

pub struct AttackGraph {
    pub graph: DiGraph<NodeData, EdgeData>,
    pub node_map: HashMap<String, NodeIndex>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, data: NodeData) -> NodeIndex {
        if let Some(&index) = self.node_map.get(&data.id) {
            return index;
        }
        let id = data.id.clone();
        let index = self.graph.add_node(data);
        self.node_map.insert(id, index);
        index
    }

    pub fn add_edge(&mut self, source_id: &str, target_id: &str, data: EdgeData) -> Option<petgraph::graph::EdgeIndex> {
        let source_idx = self.node_map.get(source_id)?;
        let target_idx = self.node_map.get(target_id)?;
        
        // Prevent duplicate edges
        if let Some(edge_idx) = self.graph.find_edge(*source_idx, *target_idx) {
            return Some(edge_idx);
        }

        Some(self.graph.add_edge(*source_idx, *target_idx, data))
    }
}

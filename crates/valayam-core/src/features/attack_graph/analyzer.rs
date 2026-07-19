use super::graph::{AttackGraph, NodeData, EdgeData};
use petgraph::algo::dijkstra;
use petgraph::graph::NodeIndex;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
pub struct CytoscapeGraph {
    pub elements: CytoscapeElements,
}

#[derive(Serialize)]
pub struct CytoscapeElements {
    pub nodes: Vec<CytoscapeNode>,
    pub edges: Vec<CytoscapeEdge>,
}

#[derive(Serialize)]
pub struct CytoscapeNode {
    pub data: NodeData,
}

#[derive(Serialize)]
pub struct CytoscapeEdgeData {
    pub source: String,
    pub target: String,
    pub label: String,
}

#[derive(Serialize)]
pub struct CytoscapeEdge {
    pub data: CytoscapeEdgeData,
}

impl AttackGraph {
    /// Find the shortest path from a given start node to a target node.
    pub fn find_kill_chain(&self, start_id: &str, target_id: &str) -> Option<Vec<String>> {
        let start_idx = self.node_map.get(start_id)?;
        let target_idx = self.node_map.get(target_id)?;

        let node_map = dijkstra(&self.graph, *start_idx, Some(*target_idx), |_| 1);
        
        if !node_map.contains_key(target_idx) {
            return None;
        }

        // Dijkstra only returns distances, we would need A* or a custom backtracer 
        // to reconstruct the path perfectly in petgraph without `astar`.
        // Since we just want to prove the concept, we can use `astar` instead.
        let path = petgraph::algo::astar(
            &self.graph,
            *start_idx,
            |finish| finish == *target_idx,
            |_| 1,
            |_| 0,
        );

        path.map(|(_, path_nodes)| {
            path_nodes.into_iter().map(|idx| self.graph[idx].id.clone()).collect()
        })
    }

    /// Export the graph in Cytoscape.js JSON format for web visualization.
    pub fn export_cytoscape(&self) -> Result<String, serde_json::Error> {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        for node_idx in self.graph.node_indices() {
            nodes.push(CytoscapeNode {
                data: self.graph[node_idx].clone(),
            });
        }

        for edge_idx in self.graph.edge_indices() {
            if let Some((source_idx, target_idx)) = self.graph.edge_endpoints(edge_idx) {
                let source_id = self.graph[source_idx].id.clone();
                let target_id = self.graph[target_idx].id.clone();
                let edge_data = &self.graph[edge_idx];

                edges.push(CytoscapeEdge {
                    data: CytoscapeEdgeData {
                        source: source_id,
                        target: target_id,
                        label: format!("{:?}", edge_data.edge_type),
                    }
                });
            }
        }

        let cyto_graph = CytoscapeGraph {
            elements: CytoscapeElements {
                nodes,
                edges,
            }
        };

        serde_json::to_string(&cyto_graph)
    }
}

use reqwest::Client;
use serde_json::json;

pub struct EvmRpcFuzzer {
    client: Client,
    endpoint: String,
}

impl EvmRpcFuzzer {
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: Client::new(),
            endpoint: endpoint.to_string(),
        }
    }

    /// Run a quick fuzz against standard eth methods with malformed inputs
    pub async fn fuzz_endpoints(&self) -> Result<Vec<String>, String> {
        let mut findings = Vec::new();

        // 1. Fuzz eth_call with malformed address
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": "0xinvalid_address", "data": "0x00"}, "latest"],
            "id": 1
        });

        match self.send_payload(&payload).await {
            Ok(res) => {
                // If it returns a 500 error or stack trace instead of standard JSON-RPC error, flag it.
                if res.status().is_server_error() {
                    findings.push("eth_call returned 500 Server Error on malformed address".to_string());
                }
            }
            Err(e) => {
                findings.push(format!("eth_call request failed: {}", e));
            }
        }

        // 2. Fuzz with massive block number
        let payload_block = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false],
            "id": 2
        });

        match self.send_payload(&payload_block).await {
            Ok(res) => {
                if res.status().is_server_error() {
                    findings.push("eth_getBlockByNumber returned 500 on massive block number".to_string());
                }
            }
            Err(e) => {
                findings.push(format!("eth_getBlockByNumber request failed: {}", e));
            }
        }

        Ok(findings)
    }

    async fn send_payload(&self, payload: &serde_json::Value) -> Result<reqwest::Response, reqwest::Error> {
        self.client.post(&self.endpoint)
            .json(payload)
            .send()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mocking an actual HTTP test would require a mock server.
    // For now, this just validates compilation.
}

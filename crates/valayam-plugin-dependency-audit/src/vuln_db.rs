use serde::Deserialize;
use reqwest::Client;

#[derive(Debug, Deserialize)]
pub struct VulnRecord {
    pub cve_id: String,
    pub severity: String,
    pub description: Option<String>,
}

pub struct ApiVulnDb {
    api_url: String,
    client: Client,
}

impl ApiVulnDb {
    pub fn new(api_url: String, client: Client) -> Self {
        Self { api_url, client }
    }

    pub async fn check_package(&self, ecosystem: &str, package: &str, _version: &str) -> Vec<VulnRecord> {
        let mut vulns = Vec::new();
        // Option A: Call the external API
        if let Ok(reqwest_url) = reqwest::Url::parse(&self.api_url) {
            if let Ok(resp) = self.client.get(reqwest_url)
                .query(&[("ecosystem", ecosystem), ("package", package)])
                // .query(&[("version", _version)]) // Can add exact version later
                .send()
                .await
            {
                if let Ok(results) = resp.json::<Vec<VulnRecord>>().await {
                    vulns = results;
                }
            }
        }
        vulns
    }
}

pub struct LocalVulnDb {
    #[allow(dead_code)]
    db_path: String,
}

impl LocalVulnDb {
    pub fn new(db_path: String) -> Self {
        Self { db_path }
    }

    pub fn check_package(&self, ecosystem: &str, package: &str, _version: &str) -> Vec<VulnRecord> {
        let conn = match rusqlite::Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to open local vuln db {}: {}", self.db_path, e);
                return Vec::new();
            }
        };

        let mut stmt = match conn.prepare(
            "SELECT v.id, v.severity, v.description 
             FROM valayam_vulns v
             JOIN vuln_packages p ON v.id = p.vuln_id
             WHERE p.ecosystem = ?1 AND p.package_name = ?2"
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to prepare query: {}", e);
                return Vec::new();
            }
        };

        let iter = match stmt.query_map(rusqlite::params![ecosystem, package], |row| {
            Ok(VulnRecord {
                cve_id: row.get(0)?,
                severity: row.get(1)?,
                description: row.get(2)?,
            })
        }) {
            Ok(i) => i,
            Err(e) => {
                tracing::error!("Failed to execute query: {}", e);
                return Vec::new();
            }
        };

        let mut vulns = Vec::new();
        for r in iter {
            if let Ok(v) = r {
                vulns.push(v);
            }
        }
        vulns
    }
}

use valayam_models::result::ScanResult;
use valayam_models::templates::schema::TemplateInfo;
use valayam_network::network::http::StealthHttpClient;
use chrono::Utc;
use valayam_models::templates::graphql_audit::GraphqlAuditTemplate;

pub async fn execute(
    target_url: &str,
    client: &StealthHttpClient,
    templates: &[GraphqlAuditTemplate],
    template_id: &str,
    template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_url);

        if template.introspection {
            if let Ok(reqwest_url) = reqwest::Url::parse(&host) {
                let req_client = client.client();
                
                let payload = serde_json::json!({
                    "query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types {\n          ...FullType\n        }\n        directives {\n          name\n          description\n          locations\n          args {\n            ...InputValue\n          }\n        }\n      }\n    }\n\n    fragment FullType on __Type {\n      kind\n      name\n      description\n      fields(includeDeprecated: true) {\n        name\n        description\n        args {\n          ...InputValue\n        }\n        type {\n          ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n      }\n      inputFields {\n        ...InputValue\n      }\n      interfaces {\n        ...TypeRef\n      }\n      enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n      }\n      possibleTypes {\n        ...TypeRef\n      }\n    }\n\n    fragment InputValue on __InputValue {\n      name\n      description\n      type { ...TypeRef }\n      defaultValue\n    }\n\n    fragment TypeRef on __Type {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n            ofType {\n              kind\n              name\n              ofType {\n                kind\n                name\n                ofType {\n                  kind\n                  name\n                  ofType {\n                    kind\n                    name\n                  }\n                }\n              }\n            }\n          }\n        }\n      }\n    }\n  "
                });

                if let Ok(resp) = req_client.post(reqwest_url.clone()).json(&payload).send().await {
                    if let Ok(body) = resp.text().await {
                        if body.contains("__schema") && body.contains("queryType") {
                            let mut results = vec![ScanResult { schema_version: "1.0.0".to_string(),
                                timestamp: Utc::now(),
                                template_id: template_id.to_string(),
                                template_name: template_info.name.clone(),
                                template_severity: "Low".to_string(), // Changed to Low, as Introspection itself is just info disclosure
                                target: host.clone(),
                                payload: "GraphQL Introspection query is enabled, exposing API schema.".to_string(),
                                cvss_score: None,
                                reference: None,
                                solution: None,
                                tags: Vec::new(),
                                compliance: Default::default(),
                            }];

                            // 1. Alias Batching DoS Attack
                            if let Some(alias_payload) = super::mutator::GraphqlMutator::generate_alias_batch_payload(&body, 100) {
                                if let Ok(atk_resp) = req_client.post(reqwest_url.clone()).json(&alias_payload).send().await {
                                    if atk_resp.status().is_server_error() || atk_resp.status().is_success() {
                                        // If it took a long time or crashed, it might be vulnerable. We'll flag it.
                                        results.push(ScanResult { schema_version: "1.0.0".to_string(),
                                            timestamp: Utc::now(),
                                            template_id: template_id.to_string(),
                                            template_name: format!("{} - Alias Batching DoS", template_info.name),
                                            template_severity: "High".to_string(),
                                            target: host.clone(),
                                            payload: "GraphQL endpoint allows extensive alias batching (100 aliases), potentially leading to Denial of Service (DoS).".to_string(),
                                            cvss_score: None,
                                            reference: None,
                                            solution: None,
                                            tags: Vec::new(),
                                            compliance: Default::default(),
                                        });
                                    }
                                }
                            }

                            // 2. Circular Fragment Attack
                            let circ_payload = super::mutator::GraphqlMutator::generate_circular_fragment_payload();
                            if let Ok(atk_resp) = req_client.post(reqwest_url.clone()).json(&circ_payload).send().await {
                                if atk_resp.status().is_server_error() {
                                    results.push(ScanResult { schema_version: "1.0.0".to_string(),
                                        timestamp: Utc::now(),
                                        template_id: template_id.to_string(),
                                        template_name: format!("{} - Circular Fragments", template_info.name),
                                        template_severity: "Critical".to_string(),
                                        target: host.clone(),
                                        payload: "GraphQL endpoint crashed (HTTP 500) when supplied with circular fragments.".to_string(),
                                        cvss_score: None,
                                        reference: None,
                                        solution: None,
                                        tags: Vec::new(),
                                        compliance: Default::default(),
                                    });
                                }
                            }

                            // Since the function signature currently returns Option<ScanResult>, we'll return the highest severity finding
                            // In a full implementation, we'd change the return type to Vec<ScanResult>.
                            // For now, return the last one (which would be the critical one if it hit)
                            return results.pop();
                        }
                    }
                }
            }
        }
    }
    None
}

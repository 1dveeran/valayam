use serde_yaml::Value;

pub struct ServerlessAnalyzer;

impl ServerlessAnalyzer {
    pub fn analyze_serverless_yml(yaml_content: &str) -> Result<Vec<String>, String> {
        let mut findings = Vec::new();
        let parsed: Value = serde_yaml::from_str(yaml_content).map_err(|e| e.to_string())?;

        // Check provider -> iamRoleStatements
        if let Some(provider) = parsed.get("provider") {
            if let Some(iam_roles) = provider.get("iamRoleStatements") {
                if let Some(roles_array) = iam_roles.as_sequence() {
                    for role in roles_array {
                        if let Some(action) = role.get("Action") {
                            if action.as_str() == Some("*") || action.as_sequence().map_or(false, |s| s.iter().any(|v| v.as_str() == Some("*"))) {
                                findings.push("Wildcard Action '*' found in provider IAM roles. This violates least privilege.".to_string());
                            }
                        }
                        if let Some(resource) = role.get("Resource") {
                            if resource.as_str() == Some("*") || resource.as_sequence().map_or(false, |s| s.iter().any(|v| v.as_str() == Some("*"))) {
                                findings.push("Wildcard Resource '*' found in provider IAM roles. This violates least privilege.".to_string());
                            }
                        }
                    }
                }
            }
        }

        // Check functions for exposed endpoints without auth
        if let Some(functions) = parsed.get("functions") {
            if let Some(funcs) = functions.as_mapping() {
                for (func_name, func_config) in funcs {
                    if let Some(events) = func_config.get("events") {
                        if let Some(events_array) = events.as_sequence() {
                            for event in events_array {
                                if let Some(http) = event.get("http") {
                                    // Check if there's no authorizer
                                    let has_auth = http.get("authorizer").is_some();
                                    if !has_auth {
                                        findings.push(format!("Function '{}' has an HTTP event without an authorizer. Verify if it should be public.", func_name.as_str().unwrap_or("Unknown")));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    pub fn analyze_aws_sam(yaml_content: &str) -> Result<Vec<String>, String> {
        let mut findings = Vec::new();
        let parsed: Value = serde_yaml::from_str(yaml_content).map_err(|e| e.to_string())?;

        if let Some(resources) = parsed.get("Resources") {
            if let Some(res_map) = resources.as_mapping() {
                for (res_name, res_config) in res_map {
                    if res_config.get("Type").and_then(|v| v.as_str()) == Some("AWS::Serverless::Function") {
                        if let Some(props) = res_config.get("Properties") {
                            // Check Policies for wildcards
                            if let Some(policies) = props.get("Policies") {
                                if let Some(policies_array) = policies.as_sequence() {
                                    for policy in policies_array {
                                        // A policy can be a managed policy string, or an inline IAM policy object
                                        if let Some(stmt) = policy.get("Statement") {
                                            if let Some(stmt_array) = stmt.as_sequence() {
                                                for s in stmt_array {
                                                    if let Some(action) = s.get("Action") {
                                                        if action.as_str() == Some("*") || action.as_sequence().map_or(false, |seq| seq.iter().any(|v| v.as_str() == Some("*"))) {
                                                            findings.push(format!("Wildcard Action '*' found in SAM function '{}' policies.", res_name.as_str().unwrap_or("Unknown")));
                                                        }
                                                    }
                                                    if let Some(resource) = s.get("Resource") {
                                                        if resource.as_str() == Some("*") || resource.as_sequence().map_or(false, |seq| seq.iter().any(|v| v.as_str() == Some("*"))) {
                                                            findings.push(format!("Wildcard Resource '*' found in SAM function '{}' policies.", res_name.as_str().unwrap_or("Unknown")));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serverless_yml_wildcards() {
        let yaml = r#"
provider:
  iamRoleStatements:
    - Effect: "Allow"
      Action: "*"
      Resource: "arn:aws:s3:::my-bucket/*"
    - Effect: "Allow"
      Action: "s3:GetObject"
      Resource: "*"
functions:
  hello:
    handler: handler.hello
    events:
      - http:
          path: hello
          method: get
        "#;
        
        let findings = ServerlessAnalyzer::analyze_serverless_yml(yaml).unwrap();
        assert!(findings.iter().any(|f| f.contains("Wildcard Action '*' found")));
        assert!(findings.iter().any(|f| f.contains("Wildcard Resource '*' found")));
        assert!(findings.iter().any(|f| f.contains("without an authorizer")));
    }
}

use crate::core::result::ScanResult;
use crate::network::http::StealthHttpClient;
use crate::template::schema::TemplateInfo;
use super::parser::DeepAnalysisTemplate;

pub async fn execute(
    client: &StealthHttpClient,
    target_url: &str,
    templates: &[DeepAnalysisTemplate],
    _template_id: &str,
    _template_info: &TemplateInfo,
) -> Option<ScanResult> {
    for t in templates {
        match t.analysis_type.as_str() {
            "llm_mutation" => {
                if let Some(res) = super::llm_mutator::mutate_and_test(client, target_url, t).await {
                    return Some(res);
                }
            }
            "wasm_decompile" | "source_map" => {
                if let Some(res) = super::client_side::analyze(client, target_url, t).await {
                    return Some(res);
                }
            }
            "artifact_recovery" => {
                if let Some(res) = super::artifact_recovery::recover(client, target_url, t).await {
                    return Some(res);
                }
            }
            _ => {
                // Log unknown analysis type
            }
        }
    }
    None
}

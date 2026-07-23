use valayam_engine::wasm_plugin::WasmPluginBridge;
use valayam_engine::traits::{ScanPlugin, ScanContext, PluginOutcome};
use valayam_core::template::schema::VulnerabilityTemplate;
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_wasm_plugin_initialization_missing_exports() {
    let wat = r#"
        (module
            (func $dummy (result i32)
                i32.const 42
            )
            (export "not_the_right_function" (func $dummy))
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).unwrap();
    
    let tmp_dir = std::env::temp_dir();
    let wasm_path = tmp_dir.join(format!("test_wasm_missing_exports_{}.wasm", uuid::Uuid::new_v4()));
    std::fs::write(&wasm_path, &wasm_bytes).unwrap();

    let plugin = WasmPluginBridge::new("test_plugin", wasm_path.clone());
    let init_result = plugin.init().await;

    assert!(init_result.is_err(), "Initialization should fail due to missing exports");
    let err_msg = init_result.unwrap_err().to_string();
    assert!(err_msg.contains("missing required export"), "Error should mention missing export");

    let _ = std::fs::remove_file(wasm_path);
}

#[tokio::test]
async fn test_wasm_plugin_execution_success() {
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (data (i32.const 0) "{\"matched\":true,\"count\":1}\00")
            (func $alloc (param i32) (result i32)
                i32.const 100
            )
            (export "valayam_alloc" (func $alloc))

            (func $exec (param i32 i32) (result i32)
                i32.const 0
            )
            (export "valayam_execute" (func $exec))
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).unwrap();
    
    let tmp_dir = std::env::temp_dir();
    let wasm_path = tmp_dir.join(format!("test_wasm_success_{}.wasm", uuid::Uuid::new_v4()));
    std::fs::write(&wasm_path, &wasm_bytes).unwrap();

    let plugin = WasmPluginBridge::new("success_plugin", wasm_path.clone());
    
    let init_result = plugin.init().await;
    assert!(init_result.is_ok(), "Init should succeed: {:?}", init_result.err());

    let (tx, _) = mpsc::channel::<valayam_engine::traits::FindingOwned>(1);
    let template_yaml = r#"
id: test-template
info:
  name: Test
  severity: info
"#;
    let template = VulnerabilityTemplate::load_from_str(template_yaml).unwrap();

    let ctx = ScanContext {
        target: "http://example.com".to_string(),
        target_host: "example.com".to_string(),
        template: Arc::new(template),
        finding_tx: tx,
        variables: Arc::new(tokio::sync::RwLock::new(valayam_engine::traits::VariableScope::new(std::collections::HashMap::new()))),
        cancellation: tokio_util::sync::CancellationToken::new(),
    };

    let outcome = plugin.execute(&ctx).await;
    
    match outcome {
        PluginOutcome::Matched { count } => {
            assert_eq!(count, 1, "Expected count to be 1");
        }
        _ => panic!("Expected execution to match, got {:?}", outcome),
    }

    let _ = std::fs::remove_file(wasm_path);
}

pub struct StaticAnalyzer;

impl StaticAnalyzer {
    /// Extremely lightweight YARA-style bytecode matcher for EVM hex.
    pub fn scan_evm_bytecode(hex_bytecode: &str) -> Vec<String> {
        let mut findings = Vec::new();

        // 1. Detect uninitialized proxy pattern:
        // A common pattern where an implementation contract has an empty constructor
        // or its initializer function isn't protected.
        // We look for common proxy standard initialization selectors, e.g. initialize() = 0x8129fc1c
        if hex_bytecode.contains("8129fc1c") && !hex_bytecode.contains("d04f2f45") {
            // Very naive check: has `initialize()` but lacks standard reentrancy/initializer guard hashes
            findings.push("Potential uninitialized proxy or missing initializer guard detected.".to_string());
        }

        // 2. Naive Reentrancy Check:
        // DELEGATECALL opcode is F4, CALL is F1. If we see a CALL followed by state-modifying opcodes 
        // (like SSTORE 55) in a specific distance, it could be a warning.
        // For static strings, we just look for F1 followed eventually by 55.
        // This is a gross simplification for demonstration purposes.
        if let Some(call_index) = hex_bytecode.find("f1") {
            if let Some(sstore_index) = hex_bytecode[call_index..].find("55") {
                if sstore_index < 50 {
                    findings.push("Potential reentrancy pattern (CALL followed closely by SSTORE).".to_string());
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_evm_bytecode() {
        // Mock bytecode with a CALL (f1) and SSTORE (55) close together
        let fake_reentrancy_bytecode = "608060405234801561001057600080fd5b506004361061002b5760003560e01cf10000550000";
        let findings = StaticAnalyzer::scan_evm_bytecode(fake_reentrancy_bytecode);
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0], "Potential reentrancy pattern (CALL followed closely by SSTORE).");
    }
}

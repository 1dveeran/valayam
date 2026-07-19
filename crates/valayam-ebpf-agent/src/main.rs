pub mod telemetry;

use std::time::Duration;
use tokio::time::sleep;
use crate::telemetry::TelemetryEvent;
// use aya::Ebpf; // Aya removed for Windows compile compatibility

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Starting Valayam eBPF Agent...");

    // In a real Linux environment, we would load the compiled BPF bytecode here.
    // let mut bpf = Ebpf::load_file("ebpf_program.o")?;
    // let program: &mut KProbe = bpf.program_mut("sys_execve").unwrap().try_into()?;
    // program.load()?;
    // program.attach("sys_execve", 0)?;

    println!("[*] eBPF framework (Aya) stub initialized. Mocking telemetry stream (Windows dev mode)...");

    // Mock telemetry loop
    loop {
        let mock_event = TelemetryEvent::ProcessExecution {
            pid: 1234,
            command: "/usr/bin/bash".to_string(),
            args: vec!["-c".to_string(), "echo 'Lateral movement detected'".to_string()],
            user_id: 0,
        };

        println!("[TELEMETRY] Generated: {:?}", mock_event);
        
        // In reality, this would be sent via gRPC to the valayam-core / worker gateway
        // let serialized = serde_json::to_string(&mock_event)?;
        // grpc_client.stream(serialized).await?;

        sleep(Duration::from_secs(5)).await;
    }
}

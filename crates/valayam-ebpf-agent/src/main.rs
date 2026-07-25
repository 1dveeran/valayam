pub mod telemetry;
pub mod grpc;

use std::time::Duration;
use tokio::time::sleep;
use crate::telemetry::TelemetryEvent;
use crate::grpc::valayam::scanner_client::ScannerClient;
use crate::grpc::valayam::TelemetryEvent as GrpcTelemetryEvent;
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
use aya::Ebpf;
#[cfg(target_os = "linux")]
use aya::programs::KProbe;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Starting Valayam eBPF Agent...");

    // Setup gRPC client
    let mut client = ScannerClient::connect("http://127.0.0.1:50051").await?;
    println!("[*] Connected to Valayam Engine gRPC server.");

    let (tx, rx) = mpsc::channel(100);

    // Spawn a task to send the stream
    tokio::spawn(async move {
        let stream = ReceiverStream::new(rx);
        if let Err(e) = client.stream_telemetry(stream).await {
            eprintln!("[!] gRPC stream error: {}", e);
        }
    });

    #[cfg(target_os = "linux")]
    {
        println!("[*] Loading eBPF programs...");
        // In a real Linux environment, we load the compiled BPF bytecode
        // let mut bpf = Ebpf::load_file("valayam_ebpf_programs.o")?;
        // let program: &mut KProbe = bpf.program_mut("sys_execve").unwrap().try_into()?;
        // program.load()?;
        // program.attach("sys_execve", 0)?;
        // 
        // Then we'd read from a PerfEventArray and send to the `tx` channel.
        // For now, this is a placeholder.
    }

    #[cfg(not(target_os = "linux"))]
    println!("[*] Non-Linux OS detected. eBPF framework (Aya) stub initialized. Mocking telemetry stream...");

    // Mock telemetry loop (runs on all platforms as a fallback/test)
    loop {
        let mock_event = TelemetryEvent::ProcessExecution {
            pid: 1234,
            command: "/usr/bin/bash".to_string(),
            args: vec!["-c".to_string(), "echo 'Lateral movement detected'".to_string()],
            user_id: 0,
        };

        println!("[TELEMETRY] Generated: {:?}", mock_event);
        
        let grpc_event = GrpcTelemetryEvent {
            event_type: "ProcessExecution".to_string(),
            payload_json: serde_json::to_string(&mock_event)?,
        };

        if tx.send(grpc_event).await.is_err() {
            eprintln!("[!] Failed to send telemetry event. Channel closed.");
            break;
        }

        sleep(Duration::from_secs(5)).await;
    }

    Ok(())
}

use async_trait::async_trait;
use super::{ScanTask, TaskBroker};
use valayam_core::core::result::ScanResult;

pub struct KafkaBroker {
    _dummy: (),
}

impl KafkaBroker {
    pub async fn new(_url: &str) -> Result<Self, String> {
        // rdkafka requires C compilation of librdkafka which requires CMake and is highly error-prone on Windows.
        // We provide a stub that documents the configuration.
        Err("Kafka broker is not compiled in this build. Please configure rdkafka and rebuild on Linux.".to_string())
    }
}

#[async_trait]
impl TaskBroker for KafkaBroker {
    async fn pull_task(&mut self) -> Result<ScanTask, String> {
        Err("Not implemented".to_string())
    }

    async fn push_result(&mut self, _task_id: &str, _result: ScanResult) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
}

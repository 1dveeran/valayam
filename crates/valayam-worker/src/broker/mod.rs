pub mod redis_driver;
pub mod rabbitmq_driver;
pub mod kafka_driver;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use valayam_core::core::result::ScanResult;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanTask {
    pub target_url: String,
    pub template_yaml: String,
    pub task_id: String,
}

#[async_trait]
pub trait TaskBroker: Send + Sync {
    /// Pulls a scanning task from the queue.
    async fn pull_task(&mut self) -> Result<ScanTask, String>;

    /// Publishes the scan results.
    async fn push_result(&mut self, task_id: &str, result: ScanResult) -> Result<(), String>;
}

/// Factory to initialize a broker based on its connection URL.
pub async fn create_broker(broker_url: &str) -> Result<Box<dyn TaskBroker>, String> {
    if broker_url.starts_with("redis://") {
        let broker = redis_driver::RedisBroker::new(broker_url).await?;
        Ok(Box::new(broker))
    } else if broker_url.starts_with("amqp://") || broker_url.starts_with("amqps://") {
        let broker = rabbitmq_driver::RabbitMQBroker::new(broker_url).await?;
        Ok(Box::new(broker))
    } else if broker_url.starts_with("kafka://") {
        let broker = kafka_driver::KafkaBroker::new(broker_url).await?;
        Ok(Box::new(broker))
    } else {
        Err(format!("Unsupported broker scheme in URL: {}", broker_url))
    }
}

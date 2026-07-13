use async_trait::async_trait;
use super::{ScanTask, TaskBroker};
use valayam_core::core::result::ScanResult;
use std::sync::{Mutex, OnceLock};

static KAFKA_SIMULATED_QUEUE: OnceLock<Mutex<Vec<ScanTask>>> = OnceLock::new();
static KAFKA_SIMULATED_RESULTS: OnceLock<Mutex<Vec<ScanResult>>> = OnceLock::new();

fn get_queue() -> &'static Mutex<Vec<ScanTask>> {
    KAFKA_SIMULATED_QUEUE.get_or_init(|| Mutex::new(Vec::new()))
}

fn get_results() -> &'static Mutex<Vec<ScanResult>> {
    KAFKA_SIMULATED_RESULTS.get_or_init(|| Mutex::new(Vec::new()))
}

pub struct KafkaBroker {
    _url: String,
}

impl KafkaBroker {
    pub async fn new(url: &str) -> Result<Self, String> {
        tracing::info!("Initializing Simulated Kafka Broker targeting: {}", url);
        Ok(Self {
            _url: url.to_string(),
        })
    }

    /// Pushes a task into the simulated Kafka queue (used for testing).
    pub fn push_task_simulation(task: ScanTask) {
        let mut queue = get_queue().lock().unwrap();
        queue.push(task);
    }

    /// Pops a result from the simulated Kafka results topic (used for testing).
    pub fn pop_result_simulation() -> Option<ScanResult> {
        let mut results = get_results().lock().unwrap();
        results.pop()
    }
}

#[async_trait]
impl TaskBroker for KafkaBroker {
    async fn pull_task(&mut self) -> Result<ScanTask, String> {
        loop {
            {
                let mut queue = get_queue().lock().unwrap();
                if let Some(task) = queue.pop() {
                    return Ok(task);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    async fn push_result(&mut self, _task_id: &str, result: ScanResult) -> Result<(), String> {
        let mut results = get_results().lock().unwrap();
        results.push(result);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_kafka_broker_simulation() {
        let mut broker = KafkaBroker::new("kafka://localhost:9092").await.unwrap();

        let task = ScanTask {
            target_url: "https://httpbin.org".to_string(),
            template_yaml: "id: test".to_string(),
            task_id: "task-123".to_string(),
        };

        KafkaBroker::push_task_simulation(task.clone());

        let pulled = broker.pull_task().await.unwrap();
        assert_eq!(pulled.task_id, "task-123");

        let result = ScanResult {
            timestamp: chrono::Utc::now(),
            target: "https://httpbin.org".to_string(),
            template_id: "test".to_string(),
            template_name: "test".to_string(),
            template_severity: "Info".to_string(),
            payload: "test".to_string(),
        };

        broker.push_result("task-123", result.clone()).await.unwrap();

        let popped = KafkaBroker::pop_result_simulation().unwrap();
        assert_eq!(popped.template_id, "test");
    }
}

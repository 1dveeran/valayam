use async_trait::async_trait;
use redis::AsyncCommands;
use super::{ScanTask, TaskBroker};
use valayam_core::core::result::ScanResult;

pub struct RedisBroker {
    _client: redis::Client,
    conn: redis::aio::MultiplexedConnection,
}

impl RedisBroker {
    pub async fn new(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| e.to_string())?;
        let conn = client.get_multiplexed_async_connection().await.map_err(|e| e.to_string())?;
        Ok(Self { _client: client, conn })
    }
}

#[async_trait]
impl TaskBroker for RedisBroker {
    async fn pull_task(&mut self) -> Result<ScanTask, String> {
        // BLPOP returns a tuple of (key, value)
        let res: Option<(String, String)> = self
            .conn
            .blpop("valayam:tasks", 0.0)
            .await
            .map_err(|e| e.to_string())?;
        
        let (_, payload) = res.ok_or_else(|| "No task returned".to_string())?;
        let task: ScanTask = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
        Ok(task)
    }

    async fn push_result(&mut self, _task_id: &str, result: ScanResult) -> Result<(), String> {
        let payload = serde_json::to_string(&result).map_err(|e| e.to_string())?;
        let _: () = self
            .conn
            .rpush("valayam:results", payload)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

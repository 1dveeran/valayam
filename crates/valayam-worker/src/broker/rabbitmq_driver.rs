use async_trait::async_trait;
use futures::StreamExt;
use lapin::{
    options::{BasicConsumeOptions, BasicPublishOptions, QueueDeclareOptions},
    types::FieldTable,
    BasicProperties, Connection, ConnectionProperties,
};
use super::{ScanTask, TaskBroker};
use valayam_core::core::result::ScanResult;

pub struct RabbitMQBroker {
    _conn: Connection,
    channel: lapin::Channel,
    consumer: lapin::Consumer,
}

impl RabbitMQBroker {
    pub async fn new(url: &str) -> Result<Self, String> {
        let conn = Connection::connect(url, ConnectionProperties::default())
            .await
            .map_err(|e| e.to_string())?;
        
        let channel = conn.create_channel().await.map_err(|e| e.to_string())?;
        
        // Declare the tasks queue
        channel
            .queue_declare(
                "valayam_tasks",
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| e.to_string())?;

        // Declare the results queue
        channel
            .queue_declare(
                "valayam_results",
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| e.to_string())?;

        let consumer = channel
            .basic_consume(
                "valayam_tasks",
                "valayam_worker",
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| e.to_string())?;

        Ok(Self { _conn: conn, channel, consumer })
    }
}

#[async_trait]
impl TaskBroker for RabbitMQBroker {
    async fn pull_task(&mut self) -> Result<ScanTask, String> {
        // Wait for the next delivery from RabbitMQ
        let delivery = self
            .consumer
            .next()
            .await
            .ok_or_else(|| "No delivery from RabbitMQ".to_string())?
            .map_err(|e| e.to_string())?;
        
        let payload = String::from_utf8(delivery.data.clone()).map_err(|e| e.to_string())?;
        let task: ScanTask = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
        
        // Ack the message immediately for simplicity (in production we might ack after execution)
        delivery.acker.ack(lapin::options::BasicAckOptions::default()).await.map_err(|e| e.to_string())?;
        Ok(task)
    }

    async fn push_result(&mut self, _task_id: &str, result: ScanResult) -> Result<(), String> {
        let payload = serde_json::to_string(&result).map_err(|e| e.to_string())?;
        self.channel
            .basic_publish(
                "",
                "valayam_results",
                BasicPublishOptions::default(),
                payload.as_bytes(),
                BasicProperties::default(),
            )
            .await
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

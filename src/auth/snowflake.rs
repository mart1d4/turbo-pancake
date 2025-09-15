use once_cell::sync::Lazy;
use snowflake::SnowflakeIdBucket;
use std::sync::Mutex;

// Initialize Snowflake Generator
pub static SNOWFLAKE_GENERATOR: Lazy<Mutex<SnowflakeIdBucket>> = Lazy::new(|| {
    let worker_id = std::env::var("SNOWFLAKE_WORKER_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("SNOWFLAKE_WORKER_ID must be a number");
    let data_center_id = std::env::var("SNOWFLAKE_DATA_CENTER_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("SNOWFLAKE_DATA_CENTER_ID must be a number");
    Mutex::new(SnowflakeIdBucket::new(worker_id, data_center_id))
});

pub fn generate_id() -> i64 {
    SNOWFLAKE_GENERATOR
        .lock()
        .expect("Failed to lock Snowflake generator mutex") // Handle poisoning
        .get_id()
}

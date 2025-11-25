use std::time::Duration;

/// Configuration for RDClient
#[derive(Debug, Clone)]
pub struct RDClientConfig {
    /// Bootstrap server URLs
    pub bootstrap_servers: Vec<String>,

    /// Health check interval (default: 10 seconds)
    pub health_check_interval: Duration,

    /// Maximum reconnection attempts (0 = infinite)
    pub reconnect_max_retries: u32,

    /// Interval between reconnection attempts (default: 5 seconds)
    pub reconnect_interval: Duration,
}

impl Default for RDClientConfig {
    fn default() -> Self {
        Self {
            bootstrap_servers: vec!["ws://localhost:4017/relay".to_string()],
            health_check_interval: Duration::from_secs(10),
            reconnect_max_retries: 9,
            reconnect_interval: Duration::from_secs(5),
        }
    }
}

impl RDClientConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_bootstrap_servers(mut self, servers: Vec<String>) -> Self {
        self.bootstrap_servers = servers;
        self
    }

    pub fn with_health_check_interval(mut self, interval: Duration) -> Self {
        self.health_check_interval = interval;
        self
    }

    pub fn with_reconnect_max_retries(mut self, retries: u32) -> Self {
        self.reconnect_max_retries = retries;
        self
    }

    pub fn with_reconnect_interval(mut self, interval: Duration) -> Self {
        self.reconnect_interval = interval;
        self
    }
}

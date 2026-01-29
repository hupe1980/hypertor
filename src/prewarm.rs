//! Circuit prewarming for reduced latency.
//!
//! Pre-builds Tor circuits in the background so they're ready when needed.

use crate::{Error, Result};
use arti_client::{TorClient as ArtiClient, TorClientConfig};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, warn};

/// Configuration for circuit prewarming.
#[derive(Debug, Clone)]
pub struct PrewarmConfig {
    /// Minimum number of prewarmed circuits to maintain.
    pub min_circuits: usize,
    /// Maximum number of prewarmed circuits.
    pub max_circuits: usize,
    /// How often to check and refill circuits.
    pub refill_interval: Duration,
    /// Maximum age of a prewarmed circuit before it's discarded.
    pub max_age: Duration,
}

impl Default for PrewarmConfig {
    fn default() -> Self {
        Self {
            min_circuits: 2,
            max_circuits: 5,
            refill_interval: Duration::from_secs(30),
            max_age: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// A prewarmed circuit ready for use.
#[derive(Debug)]
struct PrewarmedCircuit {
    /// When this circuit was created.
    created_at: Instant,
    /// Isolation token for this circuit.
    isolation_token: u64,
}

/// Circuit prewarmer that maintains a pool of ready circuits.
pub struct CircuitPrewarmer {
    config: PrewarmConfig,
    client: Arc<ArtiClient<PreferredRuntime>>,
    circuits: Arc<Mutex<VecDeque<PrewarmedCircuit>>>,
    semaphore: Arc<Semaphore>,
    shutdown: Arc<tokio::sync::Notify>,
}

impl CircuitPrewarmer {
    /// Create a new circuit prewarmer.
    pub async fn new(config: PrewarmConfig) -> Result<Self> {
        let arti_config = TorClientConfig::default();
        let client = ArtiClient::create_bootstrapped(arti_config)
            .await
            .map_err(|e| Error::bootstrap(e.to_string()))?;

        Ok(Self {
            config,
            client: Arc::new(client),
            circuits: Arc::new(Mutex::new(VecDeque::new())),
            semaphore: Arc::new(Semaphore::new(1)),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Start the background prewarming task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let circuits = Arc::clone(&self.circuits);
        let client = Arc::clone(&self.client);
        let semaphore = Arc::clone(&self.semaphore);
        let shutdown = Arc::clone(&self.shutdown);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(config.refill_interval) => {
                        // Remove expired circuits
                        {
                            let mut lock = circuits.lock();
                            lock.retain(|c| c.created_at.elapsed() < config.max_age);
                        }

                        // Refill if below minimum
                        let current_count = circuits.lock().len();
                        if current_count < config.min_circuits {
                            let to_create = config.max_circuits - current_count;
                            for _ in 0..to_create {
                                if let Ok(_permit) = semaphore.clone().try_acquire_owned() {
                                    let circuits = Arc::clone(&circuits);
                                    let client = Arc::clone(&client);
                                    let max_circuits = config.max_circuits;

                                    tokio::spawn(async move {
                                        if let Err(e) = prewarm_one(&client, &circuits, max_circuits).await {
                                            warn!(error = %e, "Failed to prewarm circuit");
                                        }
                                    });
                                }
                            }
                        }
                    }
                    _ = shutdown.notified() => {
                        debug!("Circuit prewarmer shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Get a prewarmed circuit if available.
    pub fn get(&self) -> Option<u64> {
        let mut lock = self.circuits.lock();
        while let Some(circuit) = lock.pop_front() {
            if circuit.created_at.elapsed() < self.config.max_age {
                return Some(circuit.isolation_token);
            }
            // Circuit expired, try next
        }
        None
    }

    /// Get the number of available prewarmed circuits.
    pub fn available(&self) -> usize {
        self.circuits.lock().len()
    }

    /// Signal shutdown.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }
}

async fn prewarm_one(
    client: &ArtiClient<PreferredRuntime>,
    circuits: &Mutex<VecDeque<PrewarmedCircuit>>,
    max_circuits: usize,
) -> Result<()> {
    // Create a circuit by connecting to a known endpoint
    // We use example.com as a "prewarm" target - the circuit will be reusable
    let isolation_token = rand::random::<u64>();

    // Just ensure we can build a circuit - don't actually connect
    // The circuit will be cached by arti
    let _stream = client
        .connect(("example.com", 80u16))
        .await
        .map_err(|e| Error::Circuit {
            message: format!("Failed to prewarm circuit: {}", e),
            source: Some(Box::new(e)),
        })?;

    let circuit = PrewarmedCircuit {
        created_at: Instant::now(),
        isolation_token,
    };

    let mut lock = circuits.lock();
    if lock.len() < max_circuits {
        lock.push_back(circuit);
        debug!(count = lock.len(), "Prewarmed circuit added");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_prewarm_config_default() {
        let config = PrewarmConfig::default();
        assert_eq!(config.min_circuits, 2);
        assert_eq!(config.max_circuits, 5);
    }
}

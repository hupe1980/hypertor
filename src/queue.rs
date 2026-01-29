//! Request priority queue.
//!
//! Provides priority-based request scheduling with fair queuing
//! and starvation prevention.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Semaphore;

/// Request priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Priority {
    /// Background tasks, can be delayed significantly
    Background = 0,
    /// Low priority, below normal
    Low = 1,
    /// Normal priority (default)
    #[default]
    Normal = 2,
    /// High priority, process soon
    High = 3,
    /// Critical priority, process immediately
    Critical = 4,
}

impl Priority {
    /// Get the numeric value.
    pub fn value(&self) -> u8 {
        *self as u8
    }

    /// Get the weight for fair queuing (higher = more slots).
    pub fn weight(&self) -> u32 {
        match self {
            Self::Background => 1,
            Self::Low => 2,
            Self::Normal => 4,
            Self::High => 8,
            Self::Critical => 16,
        }
    }

    /// Get the maximum wait time before priority boost.
    pub fn max_wait(&self) -> Duration {
        match self {
            Self::Background => Duration::from_secs(60),
            Self::Low => Duration::from_secs(30),
            Self::Normal => Duration::from_secs(15),
            Self::High => Duration::from_secs(5),
            Self::Critical => Duration::from_secs(1),
        }
    }
}

/// Queued request entry.
#[derive(Debug)]
pub struct QueuedRequest<T> {
    /// The request data
    pub data: T,
    /// Request priority
    pub priority: Priority,
    /// When the request was queued
    pub queued_at: Instant,
    /// Sequence number for FIFO ordering within priority
    sequence: u64,
}

impl<T> QueuedRequest<T> {
    /// Get the time spent in queue.
    pub fn wait_time(&self) -> Duration {
        self.queued_at.elapsed()
    }

    /// Get effective priority (may be boosted due to wait time).
    pub fn effective_priority(&self) -> Priority {
        let wait = self.wait_time();
        let max_wait = self.priority.max_wait();

        if wait > max_wait * 4 {
            Priority::Critical
        } else if wait > max_wait * 2 {
            match self.priority {
                Priority::Background => Priority::Low,
                Priority::Low => Priority::Normal,
                Priority::Normal => Priority::High,
                Priority::High | Priority::Critical => Priority::Critical,
            }
        } else if wait > max_wait {
            match self.priority {
                Priority::Background => Priority::Background,
                Priority::Low => Priority::Low,
                Priority::Normal => Priority::Normal,
                Priority::High => Priority::Critical,
                Priority::Critical => Priority::Critical,
            }
        } else {
            self.priority
        }
    }
}

impl<T> Eq for QueuedRequest<T> {}

impl<T> PartialEq for QueuedRequest<T> {
    fn eq(&self, other: &Self) -> bool {
        self.sequence == other.sequence
    }
}

impl<T> Ord for QueuedRequest<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher effective priority first
        let self_priority = self.effective_priority();
        let other_priority = other.effective_priority();

        match self_priority.cmp(&other_priority) {
            Ordering::Equal => {
                // Same priority: FIFO (lower sequence first)
                other.sequence.cmp(&self.sequence)
            }
            other => other,
        }
    }
}

impl<T> PartialOrd for QueuedRequest<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Priority queue configuration.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Maximum queue size
    pub max_size: usize,
    /// Maximum concurrent requests
    pub max_concurrent: usize,
    /// Whether to enable priority boosting
    pub enable_boosting: bool,
    /// Cleanup interval for stale requests
    pub cleanup_interval: Duration,
    /// Maximum time a request can stay in queue
    pub max_queue_time: Duration,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_size: 10000,
            max_concurrent: 100,
            enable_boosting: true,
            cleanup_interval: Duration::from_secs(10),
            max_queue_time: Duration::from_secs(300),
        }
    }
}

impl QueueConfig {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum queue size.
    #[must_use]
    pub fn with_max_size(mut self, max: usize) -> Self {
        self.max_size = max;
        self
    }

    /// Set maximum concurrent requests.
    #[must_use]
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Enable or disable priority boosting.
    #[must_use]
    pub fn with_boosting(mut self, enabled: bool) -> Self {
        self.enable_boosting = enabled;
        self
    }
}

/// Priority-based request queue.
#[derive(Debug)]
pub struct PriorityQueue<T> {
    config: QueueConfig,
    queue: Arc<Mutex<BinaryHeap<QueuedRequest<T>>>>,
    sequence: AtomicU64,
    semaphore: Arc<Semaphore>,
    stats: Arc<QueueStats>,
}

impl<T: Send + 'static> PriorityQueue<T> {
    /// Create a new priority queue.
    pub fn new(config: QueueConfig) -> Self {
        let max_concurrent = config.max_concurrent;
        Self {
            config,
            queue: Arc::new(Mutex::new(BinaryHeap::new())),
            sequence: AtomicU64::new(0),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            stats: Arc::new(QueueStats::new()),
        }
    }

    /// Enqueue a request with normal priority.
    pub fn push(&self, data: T) -> Result<(), QueueError> {
        self.push_with_priority(data, Priority::Normal)
    }

    /// Enqueue a request with a specific priority.
    pub fn push_with_priority(&self, data: T, priority: Priority) -> Result<(), QueueError> {
        let mut queue = self.queue.lock();

        if queue.len() >= self.config.max_size {
            self.stats.rejected.fetch_add(1, AtomicOrdering::Relaxed);
            return Err(QueueError::QueueFull);
        }

        let request = QueuedRequest {
            data,
            priority,
            queued_at: Instant::now(),
            sequence: self.sequence.fetch_add(1, AtomicOrdering::Relaxed),
        };

        queue.push(request);
        self.stats.enqueued.fetch_add(1, AtomicOrdering::Relaxed);
        self.stats.update_size(queue.len());

        Ok(())
    }

    /// Try to dequeue the highest priority request.
    pub fn pop(&self) -> Option<QueuedRequest<T>> {
        let mut queue = self.queue.lock();
        let request = queue.pop();

        if request.is_some() {
            self.stats.dequeued.fetch_add(1, AtomicOrdering::Relaxed);
            self.stats.update_size(queue.len());
        }

        request
    }

    /// Wait for a slot and dequeue.
    pub async fn acquire(&self) -> Option<(QueuedRequest<T>, QueuePermit)> {
        let permit = self.semaphore.clone().acquire_owned().await.ok()?;
        let request = self.pop()?;

        let wait_time = request.wait_time();
        self.stats
            .total_wait_ms
            .fetch_add(wait_time.as_millis() as u64, AtomicOrdering::Relaxed);

        Some((request, QueuePermit { _permit: permit }))
    }

    /// Get the current queue length.
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    /// Get queue statistics.
    pub fn stats(&self) -> QueueStatistics {
        let dequeued = self.stats.dequeued.load(AtomicOrdering::Relaxed);
        let total_wait = self.stats.total_wait_ms.load(AtomicOrdering::Relaxed);

        QueueStatistics {
            current_size: self.len(),
            enqueued: self.stats.enqueued.load(AtomicOrdering::Relaxed),
            dequeued,
            rejected: self.stats.rejected.load(AtomicOrdering::Relaxed),
            max_size_reached: self.stats.max_size.load(AtomicOrdering::Relaxed),
            avg_wait_ms: if dequeued > 0 {
                total_wait / dequeued
            } else {
                0
            },
        }
    }

    /// Remove stale requests from the queue.
    pub fn cleanup(&self) {
        let mut queue = self.queue.lock();
        let max_time = self.config.max_queue_time;

        // Rebuild queue without stale entries
        let valid: Vec<_> = queue
            .drain()
            .filter(|r| r.queued_at.elapsed() < max_time)
            .collect();

        let removed = queue.len();
        for item in valid {
            queue.push(item);
        }

        if removed > 0 {
            self.stats.update_size(queue.len());
        }
    }

    /// Clear the queue.
    pub fn clear(&self) {
        let mut queue = self.queue.lock();
        queue.clear();
        self.stats.update_size(0);
    }
}

/// Permit returned when a request is acquired.
#[derive(Debug)]
pub struct QueuePermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Queue error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    /// Queue is full
    QueueFull,
    /// Request timeout
    Timeout,
    /// Queue is closed
    Closed,
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => write!(f, "queue is full"),
            Self::Timeout => write!(f, "request timeout"),
            Self::Closed => write!(f, "queue is closed"),
        }
    }
}

impl std::error::Error for QueueError {}

/// Internal statistics tracking.
#[derive(Debug)]
struct QueueStats {
    enqueued: AtomicU64,
    dequeued: AtomicU64,
    rejected: AtomicU64,
    max_size: AtomicU64,
    total_wait_ms: AtomicU64,
}

impl QueueStats {
    fn new() -> Self {
        Self {
            enqueued: AtomicU64::new(0),
            dequeued: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            max_size: AtomicU64::new(0),
            total_wait_ms: AtomicU64::new(0),
        }
    }

    fn update_size(&self, size: usize) {
        let current_max = self.max_size.load(AtomicOrdering::Relaxed);
        if size as u64 > current_max {
            self.max_size.store(size as u64, AtomicOrdering::Relaxed);
        }
    }
}

/// Queue statistics snapshot.
#[derive(Debug, Clone)]
pub struct QueueStatistics {
    /// Current queue size
    pub current_size: usize,
    /// Total requests enqueued
    pub enqueued: u64,
    /// Total requests dequeued
    pub dequeued: u64,
    /// Total requests rejected
    pub rejected: u64,
    /// Maximum size reached
    pub max_size_reached: u64,
    /// Average wait time in milliseconds
    pub avg_wait_ms: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical > Priority::High);
        assert!(Priority::High > Priority::Normal);
        assert!(Priority::Normal > Priority::Low);
        assert!(Priority::Low > Priority::Background);
    }

    #[test]
    fn test_priority_queue_basic() {
        let queue: PriorityQueue<&str> = PriorityQueue::new(QueueConfig::default());

        queue.push_with_priority("low", Priority::Low).unwrap();
        queue.push_with_priority("high", Priority::High).unwrap();
        queue
            .push_with_priority("normal", Priority::Normal)
            .unwrap();

        // Should come out in priority order
        assert_eq!(queue.pop().unwrap().data, "high");
        assert_eq!(queue.pop().unwrap().data, "normal");
        assert_eq!(queue.pop().unwrap().data, "low");
    }

    #[test]
    fn test_priority_queue_fifo_within_priority() {
        let queue: PriorityQueue<u32> = PriorityQueue::new(QueueConfig::default());

        queue.push_with_priority(1, Priority::Normal).unwrap();
        queue.push_with_priority(2, Priority::Normal).unwrap();
        queue.push_with_priority(3, Priority::Normal).unwrap();

        // Should be FIFO within same priority
        assert_eq!(queue.pop().unwrap().data, 1);
        assert_eq!(queue.pop().unwrap().data, 2);
        assert_eq!(queue.pop().unwrap().data, 3);
    }

    #[test]
    fn test_queue_full() {
        let config = QueueConfig::new().with_max_size(2);
        let queue: PriorityQueue<u32> = PriorityQueue::new(config);

        queue.push(1).unwrap();
        queue.push(2).unwrap();
        assert_eq!(queue.push(3), Err(QueueError::QueueFull));
    }

    #[test]
    fn test_queue_stats() {
        let queue: PriorityQueue<u32> = PriorityQueue::new(QueueConfig::default());

        queue.push(1).unwrap();
        queue.push(2).unwrap();
        let _ = queue.pop();

        let stats = queue.stats();
        assert_eq!(stats.enqueued, 2);
        assert_eq!(stats.dequeued, 1);
        assert_eq!(stats.current_size, 1);
    }

    #[test]
    fn test_effective_priority_boost() {
        let request = QueuedRequest {
            data: "test",
            priority: Priority::Low,
            queued_at: Instant::now() - Duration::from_secs(120), // 2 minutes ago
            sequence: 0,
        };

        // Should be boosted due to long wait
        assert!(request.effective_priority() > Priority::Low);
    }
}

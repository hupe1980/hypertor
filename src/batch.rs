//! Request batching for efficient bulk operations.
//!
//! Groups multiple requests together to reduce overhead and improve
//! throughput for bulk operations over Tor.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex, RwLock};

/// Batch configuration.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum batch size
    pub max_size: usize,
    /// Maximum time to wait for batch to fill
    pub max_wait: Duration,
    /// Minimum batch size before sending
    pub min_size: usize,
    /// Enable adaptive batching
    pub adaptive: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_size: 50,
            max_wait: Duration::from_millis(100),
            min_size: 1,
            adaptive: true,
        }
    }
}

impl BatchConfig {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum batch size.
    #[must_use]
    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    /// Set maximum wait time.
    #[must_use]
    pub fn with_max_wait(mut self, wait: Duration) -> Self {
        self.max_wait = wait;
        self
    }

    /// Set minimum batch size.
    #[must_use]
    pub fn with_min_size(mut self, size: usize) -> Self {
        self.min_size = size;
        self
    }

    /// Create a high-throughput configuration.
    pub fn high_throughput() -> Self {
        Self {
            max_size: 200,
            max_wait: Duration::from_millis(50),
            min_size: 10,
            adaptive: true,
        }
    }

    /// Create a low-latency configuration.
    pub fn low_latency() -> Self {
        Self {
            max_size: 10,
            max_wait: Duration::from_millis(10),
            min_size: 1,
            adaptive: false,
        }
    }
}

/// A batch request item.
#[derive(Debug)]
pub struct BatchItem<T> {
    /// The actual request data
    pub data: T,
    /// Time the item was added
    pub added_at: Instant,
    /// Priority (higher = more important)
    pub priority: u8,
}

impl<T> BatchItem<T> {
    /// Create a new batch item.
    pub fn new(data: T) -> Self {
        Self {
            data,
            added_at: Instant::now(),
            priority: 5,
        }
    }

    /// Create with priority.
    pub fn with_priority(data: T, priority: u8) -> Self {
        Self {
            data,
            added_at: Instant::now(),
            priority,
        }
    }

    /// Get time spent waiting.
    pub fn wait_time(&self) -> Duration {
        self.added_at.elapsed()
    }
}

/// A batch of requests ready for processing.
#[derive(Debug)]
pub struct Batch<T> {
    /// Items in the batch
    pub items: Vec<BatchItem<T>>,
    /// Batch creation time
    pub created_at: Instant,
    /// Batch ID
    pub id: u64,
}

impl<T> Batch<T> {
    /// Get batch size.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if batch is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get average wait time.
    pub fn avg_wait_time(&self) -> Duration {
        if self.items.is_empty() {
            return Duration::ZERO;
        }
        let total: Duration = self.items.iter().map(|i| i.wait_time()).sum();
        total / self.items.len() as u32
    }

    /// Get maximum wait time.
    pub fn max_wait_time(&self) -> Duration {
        self.items
            .iter()
            .map(|i| i.wait_time())
            .max()
            .unwrap_or(Duration::ZERO)
    }

    /// Get items sorted by priority.
    pub fn into_sorted(mut self) -> Vec<BatchItem<T>> {
        self.items.sort_by(|a, b| b.priority.cmp(&a.priority));
        self.items
    }
}

/// Batcher for collecting requests into batches.
#[derive(Debug)]
pub struct Batcher<T> {
    config: BatchConfig,
    /// Pending items
    pending: Mutex<VecDeque<BatchItem<T>>>,
    /// Condition variable for waiting
    condvar: Condvar,
    /// Batch counter
    batch_counter: AtomicU64,
    /// Total items batched
    total_items: AtomicU64,
    /// Total batches created
    total_batches: AtomicU64,
    /// Current adaptive batch size
    adaptive_size: AtomicUsize,
    /// Last batch time
    last_batch: RwLock<Instant>,
}

impl<T> Batcher<T> {
    /// Create a new batcher.
    pub fn new(config: BatchConfig) -> Self {
        let initial_size = config.max_size;
        Self {
            pending: Mutex::new(VecDeque::new()),
            condvar: Condvar::new(),
            batch_counter: AtomicU64::new(0),
            total_items: AtomicU64::new(0),
            total_batches: AtomicU64::new(0),
            adaptive_size: AtomicUsize::new(initial_size),
            last_batch: RwLock::new(Instant::now()),
            config,
        }
    }

    /// Add an item to the batcher.
    pub fn add(&self, item: T) {
        let batch_item = BatchItem::new(item);
        self.add_item(batch_item);
    }

    /// Add an item with priority.
    pub fn add_with_priority(&self, item: T, priority: u8) {
        let batch_item = BatchItem::with_priority(item, priority);
        self.add_item(batch_item);
    }

    fn add_item(&self, item: BatchItem<T>) {
        let mut pending = self.pending.lock();
        pending.push_back(item);
        self.total_items.fetch_add(1, Ordering::Relaxed);

        // Notify if batch might be ready
        let target = self.current_target_size();
        if pending.len() >= target {
            self.condvar.notify_all();
        }
    }

    /// Try to get a batch immediately without waiting.
    pub fn try_take(&self) -> Option<Batch<T>> {
        let mut pending = self.pending.lock();

        if pending.len() < self.config.min_size {
            return None;
        }

        // Check if oldest item has waited long enough
        if let Some(oldest) = pending.front() {
            if oldest.wait_time() < self.config.max_wait
                && pending.len() < self.current_target_size()
            {
                return None;
            }
        }

        self.create_batch(&mut pending)
    }

    /// Wait for a batch to be ready.
    pub fn take(&self, timeout: Duration) -> Option<Batch<T>> {
        let mut pending = self.pending.lock();
        let deadline = Instant::now() + timeout;

        loop {
            let target = self.current_target_size();

            // Check if batch is ready
            if pending.len() >= target {
                return self.create_batch(&mut pending);
            }

            // Check if any items have waited too long
            if let Some(oldest) = pending.front() {
                if oldest.wait_time() >= self.config.max_wait
                    && pending.len() >= self.config.min_size
                {
                    return self.create_batch(&mut pending);
                }
            }

            // Calculate wait time
            let wait = if let Some(oldest) = pending.front() {
                let remaining = self.config.max_wait.saturating_sub(oldest.wait_time());
                remaining.min(deadline.saturating_duration_since(Instant::now()))
            } else {
                deadline.saturating_duration_since(Instant::now())
            };

            if wait.is_zero() {
                return if pending.len() >= self.config.min_size {
                    self.create_batch(&mut pending)
                } else {
                    None
                };
            }

            // Wait for more items or timeout
            let result = self.condvar.wait_for(&mut pending, wait);
            if result.timed_out() && pending.len() < self.config.min_size {
                return None;
            }
        }
    }

    fn create_batch(&self, pending: &mut VecDeque<BatchItem<T>>) -> Option<Batch<T>> {
        if pending.is_empty() {
            return None;
        }

        let target = self.current_target_size();
        let count = pending.len().min(target);

        let items: Vec<_> = pending.drain(..count).collect();
        let batch_id = self.batch_counter.fetch_add(1, Ordering::Relaxed);
        self.total_batches.fetch_add(1, Ordering::Relaxed);

        // Update adaptive size based on performance
        if self.config.adaptive {
            self.adapt_batch_size(&items);
        }

        *self.last_batch.write() = Instant::now();

        Some(Batch {
            items,
            created_at: Instant::now(),
            id: batch_id,
        })
    }

    fn adapt_batch_size(&self, items: &[BatchItem<T>]) {
        if items.is_empty() {
            return;
        }

        // Calculate average wait time
        let total_wait: Duration = items.iter().map(|i| i.wait_time()).sum();
        let avg_wait = total_wait / items.len() as u32;

        let current = self.adaptive_size.load(Ordering::Relaxed);

        // If items wait too long, decrease batch size
        // If items don't wait long, increase batch size
        let new_size = if avg_wait > self.config.max_wait {
            (current * 9 / 10).max(self.config.min_size)
        } else if avg_wait < self.config.max_wait / 2 {
            (current * 11 / 10).min(self.config.max_size)
        } else {
            current
        };

        self.adaptive_size.store(new_size, Ordering::Relaxed);
    }

    fn current_target_size(&self) -> usize {
        if self.config.adaptive {
            self.adaptive_size.load(Ordering::Relaxed)
        } else {
            self.config.max_size
        }
    }

    /// Get current pending count.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// Get statistics.
    pub fn stats(&self) -> BatcherStats {
        let pending = self.pending.lock();
        let oldest_wait = pending
            .front()
            .map(|i| i.wait_time())
            .unwrap_or(Duration::ZERO);

        BatcherStats {
            pending_items: pending.len(),
            total_items: self.total_items.load(Ordering::Relaxed),
            total_batches: self.total_batches.load(Ordering::Relaxed),
            current_target_size: self.current_target_size(),
            oldest_wait,
            time_since_last_batch: self.last_batch.read().elapsed(),
        }
    }

    /// Flush all pending items as a batch.
    pub fn flush(&self) -> Option<Batch<T>> {
        let mut pending = self.pending.lock();
        if pending.is_empty() {
            return None;
        }

        let items: Vec<_> = pending.drain(..).collect();
        let batch_id = self.batch_counter.fetch_add(1, Ordering::Relaxed);
        self.total_batches.fetch_add(1, Ordering::Relaxed);
        *self.last_batch.write() = Instant::now();

        Some(Batch {
            items,
            created_at: Instant::now(),
            id: batch_id,
        })
    }
}

impl<T> Default for Batcher<T> {
    fn default() -> Self {
        Self::new(BatchConfig::default())
    }
}

/// Batcher statistics.
#[derive(Debug, Clone)]
pub struct BatcherStats {
    /// Currently pending items
    pub pending_items: usize,
    /// Total items ever added
    pub total_items: u64,
    /// Total batches created
    pub total_batches: u64,
    /// Current target batch size
    pub current_target_size: usize,
    /// Wait time of oldest pending item
    pub oldest_wait: Duration,
    /// Time since last batch
    pub time_since_last_batch: Duration,
}

impl BatcherStats {
    /// Calculate average batch size.
    pub fn avg_batch_size(&self) -> f64 {
        if self.total_batches == 0 {
            return 0.0;
        }
        self.total_items as f64 / self.total_batches as f64
    }
}

/// Batch processor trait for handling batches.
pub trait BatchProcessor<T, R> {
    /// Process a batch of items.
    fn process(&self, batch: Batch<T>) -> Vec<R>;
}

/// Simple batch processor using a closure.
pub struct FnBatchProcessor<T, R, F>
where
    F: Fn(Vec<T>) -> Vec<R>,
{
    processor: F,
    _phantom: std::marker::PhantomData<(T, R)>,
}

impl<T, R, F> FnBatchProcessor<T, R, F>
where
    F: Fn(Vec<T>) -> Vec<R>,
{
    /// Create a new function-based processor.
    pub fn new(processor: F) -> Self {
        Self {
            processor,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T, R, F> BatchProcessor<T, R> for FnBatchProcessor<T, R, F>
where
    F: Fn(Vec<T>) -> Vec<R>,
{
    fn process(&self, batch: Batch<T>) -> Vec<R> {
        let data: Vec<T> = batch.items.into_iter().map(|i| i.data).collect();
        (self.processor)(data)
    }
}

/// Async batch executor.
pub struct BatchExecutor<T: Send + 'static> {
    batcher: Arc<Batcher<T>>,
}

impl<T: Send + 'static> BatchExecutor<T> {
    /// Create a new executor.
    pub fn new(config: BatchConfig) -> Self {
        Self {
            batcher: Arc::new(Batcher::new(config)),
        }
    }

    /// Get a reference to the batcher.
    pub fn batcher(&self) -> &Arc<Batcher<T>> {
        &self.batcher
    }

    /// Submit an item.
    pub fn submit(&self, item: T) {
        self.batcher.add(item);
    }

    /// Submit with priority.
    pub fn submit_with_priority(&self, item: T, priority: u8) {
        self.batcher.add_with_priority(item, priority);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_batch_creation() {
        let batcher: Batcher<u32> = Batcher::default();

        // Add items
        for i in 0..10 {
            batcher.add(i);
        }

        assert_eq!(batcher.pending_count(), 10);

        // Should not get batch yet (min not met with timeout)
        let batch = batcher.try_take();
        assert!(batch.is_none());
    }

    #[test]
    fn test_batch_full() {
        let config = BatchConfig::default().with_max_size(5).with_min_size(5);
        let batcher: Batcher<u32> = Batcher::new(config);

        // Add exactly max_size items
        for i in 0..5 {
            batcher.add(i);
        }

        // Should get batch now
        let batch = batcher.try_take().unwrap();
        assert_eq!(batch.len(), 5);
    }

    #[test]
    fn test_flush() {
        let batcher: Batcher<u32> = Batcher::default();

        for i in 0..3 {
            batcher.add(i);
        }

        let batch = batcher.flush().unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(batcher.pending_count(), 0);
    }

    #[test]
    fn test_priority() {
        let batcher: Batcher<&str> = Batcher::default();

        batcher.add_with_priority("low", 1);
        batcher.add_with_priority("high", 9);
        batcher.add_with_priority("medium", 5);

        let batch = batcher.flush().unwrap();
        let sorted = batch.into_sorted();

        assert_eq!(sorted[0].data, "high");
        assert_eq!(sorted[1].data, "medium");
        assert_eq!(sorted[2].data, "low");
    }

    #[test]
    fn test_stats() {
        let batcher: Batcher<u32> = Batcher::default();

        for i in 0..10 {
            batcher.add(i);
        }

        let stats = batcher.stats();
        assert_eq!(stats.pending_items, 10);
        assert_eq!(stats.total_items, 10);
    }
}

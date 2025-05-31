---
description:
globs:
alwaysApply: false
---
# ⚡ RUST CONCURRENCY BEST PRACTICES

> **TL;DR:** Modern async/await patterns and thread-safe data structures for high-performance Rust applications.

## 🔍 CONCURRENCY ARCHITECTURE STRATEGY

```mermaid
graph TD
    Start["Concurrency Requirements"] --> ConcurrencyType{"Concurrency<br>Pattern?"}

    ConcurrencyType -->|Async I/O| AsyncPattern["Async/Await Pattern"]
    ConcurrencyType -->|CPU Intensive| ParallelPattern["Parallel Processing"]
    ConcurrencyType -->|Shared State| SharedStatePattern["Shared State Management"]
    ConcurrencyType -->|Message Passing| MessagePattern["Message Passing"]

    AsyncPattern --> TokioRuntime["Tokio Runtime"]
    ParallelPattern --> Rayon["Rayon Parallel Iterators"]
    SharedStatePattern --> DashMap["DashMap Collections"]
    MessagePattern --> Channels["Channel Communication"]

    TokioRuntime --> AsyncPrimitives["Async Sync Primitives"]
    Rayon --> ThreadPool["Thread Pool Management"]
    DashMap --> LockFree["Lock-Free Data Structures"]
    Channels --> ChannelTypes["Channel Type Selection"]

    AsyncPrimitives --> ErrorHandling["Error Handling"]
    ThreadPool --> ErrorHandling
    LockFree --> ErrorHandling
    ChannelTypes --> ErrorHandling

    ErrorHandling --> Testing["Concurrency Testing"]
    Testing --> Performance["Performance Monitoring"]
    Performance --> Production["Production Concurrency"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style AsyncPattern fill:#4dbb5f,stroke:#36873f,color:white
    style SharedStatePattern fill:#ffa64d,stroke:#cc7a30,color:white
    style MessagePattern fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 ASYNC RUNTIME SELECTION

### Tokio as the Standard
- **Always use Tokio** for async runtime
- **Use tokio::sync primitives** instead of std::sync for async code
- **Leverage async/await patterns** throughout the application
- **Avoid blocking operations** in async contexts

```toml
# Cargo.toml - Tokio configuration
[dependencies]
tokio = { version = "1.45", features = [
    "macros",
    "rt-multi-thread",
    "signal",
    "sync"
] }
dashmap = { version = "6", features = ["serde"] }
async-trait = "0.1"
futures = "0.3"
```

## 🔒 SYNCHRONIZATION PRIMITIVES

### Tokio Sync Over Std Sync
```rust
// ✅ Preferred: Use tokio synchronization primitives
use tokio::sync::{RwLock, Mutex, broadcast, mpsc, oneshot};
use std::sync::Arc;

// ✅ Good: Async-friendly RwLock
pub struct UserCache {
    data: Arc<RwLock<HashMap<String, User>>>,
}

impl UserCache {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get(&self, id: &str) -> Option<User> {
        let data = self.data.read().await;
        data.get(id).cloned()
    }

    pub async fn insert(&self, id: String, user: User) {
        let mut data = self.data.write().await;
        data.insert(id, user);
    }

    pub async fn remove(&self, id: &str) -> Option<User> {
        let mut data = self.data.write().await;
        data.remove(id)
    }
}

// ❌ Avoid: std::sync in async contexts
// use std::sync::{RwLock, Mutex};  // Blocks async runtime
// use parking_lot::{RwLock, Mutex}; // Also blocking
```

### DashMap for Concurrent Collections
```rust
use dashmap::DashMap;
use std::sync::Arc;

// ✅ Preferred: DashMap for concurrent hash maps
pub struct ServiceRegistry {
    services: Arc<DashMap<String, Box<dyn Service>>>,
    categories: Arc<DashMap<String, Vec<String>>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: Arc::new(DashMap::new()),
            categories: Arc::new(DashMap::new()),
        }
    }

    pub fn register_service(&self, id: String, service: Box<dyn Service>) {
        let category = service.category().to_string();

        // Insert the service
        self.services.insert(id.clone(), service);

        // Update category index
        self.categories
            .entry(category)
            .or_insert_with(Vec::new)
            .push(id);
    }

    pub fn get_service(&self, id: &str) -> Option<dashmap::mapref::one::Ref<String, Box<dyn Service>>> {
        self.services.get(id)
    }

    pub fn list_by_category(&self, category: &str) -> Vec<String> {
        self.categories
            .get(category)
            .map(|entry| entry.clone())
            .unwrap_or_default()
    }

    pub fn list_all_services(&self) -> Vec<String> {
        self.services.iter().map(|entry| entry.key().clone()).collect()
    }
}

// ❌ Avoid: Mutex<HashMap> for concurrent access
// pub struct BadServiceRegistry {
//     services: Arc<Mutex<HashMap<String, Box<dyn Service>>>>
// }
```

## 📡 CHANNEL PATTERNS

### Multi-Producer Single-Consumer (MPSC)
```rust
use tokio::sync::mpsc;
use tracing::{info, error};

pub struct EventProcessor {
    sender: mpsc::UnboundedSender<SystemEvent>,
}

impl EventProcessor {
    pub fn new() -> (Self, EventProcessorHandle) {
        let (tx, rx) = mpsc::unbounded_channel();

        let handle = EventProcessorHandle::new(rx);
        let processor = Self { sender: tx };

        (processor, handle)
    }

    pub fn send_event(&self, event: SystemEvent) -> Result<(), mpsc::error::SendError<SystemEvent>> {
        self.sender.send(event)
    }
}

pub struct EventProcessorHandle {
    receiver: mpsc::UnboundedReceiver<SystemEvent>,
}

impl EventProcessorHandle {
    fn new(receiver: mpsc::UnboundedReceiver<SystemEvent>) -> Self {
        Self { receiver }
    }

    pub async fn run(mut self) {
        while let Some(event) = self.receiver.recv().await {
            if let Err(e) = self.process_event(event).await {
                error!("Failed to process event: {}", e);
            }
        }
        info!("Event processor stopped");
    }

    async fn process_event(&self, event: SystemEvent) -> Result<(), ProcessingError> {
        match event {
            SystemEvent::UserRegistered { user_id, .. } => {
                info!("User {} registered", user_id);
                // Process user registration
            }
            SystemEvent::OrderCompleted { order_id, .. } => {
                info!("Order {} completed", order_id);
                // Process order completion
            }
            SystemEvent::PaymentFailed { payment_id, error, .. } => {
                error!("Payment {} failed: {}", payment_id, error);
                // Process payment failure
            }
        }
        Ok(())
    }
}
```

### Broadcast for Multiple Subscribers
```rust
use tokio::sync::broadcast;

pub struct EventBus {
    sender: broadcast::Sender<SystemEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: SystemEvent) -> Result<usize, broadcast::error::SendError<SystemEvent>> {
        self.sender.send(event)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SystemEvent> {
        self.sender.subscribe()
    }
}

// Usage example
pub async fn start_event_monitoring(event_bus: Arc<EventBus>) {
    let mut receiver = event_bus.subscribe();

    tokio::spawn(async move {
        while let Ok(event) = receiver.recv().await {
            match event {
                SystemEvent::UserRegistered { user_id, .. } => {
                    info!("User {} registered", user_id);
                }
                SystemEvent::OrderCompleted { order_id, .. } => {
                    info!("Order {} completed", order_id);
                }
                SystemEvent::SystemShutdown => {
                    info!("System shutdown requested");
                    break;
                }
            }
        }
    });
}
```

### Oneshot for Single Response
```rust
use tokio::sync::oneshot;

pub struct AsyncValidator {
    // Internal state
}

impl AsyncValidator {
    pub async fn validate_user(&self, user: User) -> Result<ValidationResult, ValidationError> {
        let (tx, rx) = oneshot::channel();

        // Spawn validation task
        let user_clone = user.clone();
        tokio::spawn(async move {
            let result = perform_validation(user_clone).await;
            let _ = tx.send(result);
        });

        // Wait for validation result
        rx.await
            .map_err(|_| ValidationError::Internal("Validation task cancelled".to_string()))?
    }
}

async fn perform_validation(user: User) -> Result<ValidationResult, ValidationError> {
    // Expensive validation logic
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    if user.email.is_empty() {
        return Err(ValidationError::EmptyEmail);
    }

    Ok(ValidationResult::Valid)
}
```

## 🏃 TASK MANAGEMENT

### Structured Concurrency with JoinSet
```rust
use tokio::task::JoinSet;
use std::collections::HashMap;

pub struct BatchProcessor {
    // Internal state
}

impl BatchProcessor {
    pub async fn process_batch_parallel(&self, items: &[ProcessingItem]) -> Result<BatchResult, ProcessingError> {
        let mut join_set = JoinSet::new();
        let mut results = HashMap::new();

        // Process items in parallel where possible
        for item in items {
            if self.can_process_parallel(item, &results) {
                let item_clone = item.clone();
                let processor = self.clone();

                join_set.spawn(async move {
                    let result = processor.process_item(&item_clone).await;
                    (item_clone.id.clone(), result)
                });
            }
        }

        // Collect results
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((item_id, processing_result)) => {
                    results.insert(item_id, processing_result?);
                }
                Err(join_error) => {
                    return Err(ProcessingError::TaskFailed(join_error.to_string()));
                }
            }
        }

        Ok(BatchResult { item_results: results })
    }

    fn can_process_parallel(&self, item: &ProcessingItem, completed_results: &HashMap<String, ItemResult>) -> bool {
        // Check if all dependencies are satisfied
        item.dependencies.iter().all(|dep| completed_results.contains_key(dep))
    }
}
```

### Graceful Shutdown Pattern
```rust
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

pub struct Application {
    shutdown_token: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Application {
    pub fn new() -> Self {
        Self {
            shutdown_token: CancellationToken::new(),
            tasks: Vec::new(),
        }
    }

    pub async fn start(&mut self) -> Result<(), ApplicationError> {
        // Start background services
        self.start_user_service().await?;
        self.start_event_processor().await?;
        self.start_health_monitor().await?;

        // Wait for shutdown signal
        self.wait_for_shutdown().await;

        // Graceful shutdown
        self.shutdown_gracefully().await
    }

    async fn start_user_service(&mut self) -> Result<(), ApplicationError> {
        let token = self.shutdown_token.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        info!("User service shutdown requested");
                        break;
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                        // Process user operations
                    }
                }
            }
        });

        self.tasks.push(handle);
        Ok(())
    }

    async fn wait_for_shutdown(&self) {
        // Listen for shutdown signals
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();

        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = sigint.recv() => info!("Received SIGINT"),
        }

        self.shutdown_token.cancel();
    }

    async fn shutdown_gracefully(&mut self) -> Result<(), ApplicationError> {
        info!("Starting graceful shutdown");

        // Wait for all tasks to complete with timeout
        let shutdown_timeout = tokio::time::Duration::from_secs(30);

        tokio::time::timeout(shutdown_timeout, async {
            for handle in self.tasks.drain(..) {
                if let Err(e) = handle.await {
                    error!("Task failed during shutdown: {}", e);
                }
            }
        }).await.map_err(|_| ApplicationError::ShutdownTimeout)?;

        info!("Graceful shutdown completed");
        Ok(())
    }
}
```

## 🧪 TESTING CONCURRENT CODE

### Testing Async Functions
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_user_cache_concurrent_access() {
        let cache = UserCache::new();
        let user = User::default();

        // Test concurrent insertions
        let mut handles = Vec::new();

        for i in 0..10 {
            let cache_clone = cache.clone();
            let user_clone = user.clone();

            handles.push(tokio::spawn(async move {
                cache_clone.insert(format!("user_{}", i), user_clone).await;
            }));
        }

        // Wait for all insertions
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all users were inserted
        for i in 0..10 {
            let result = cache.get(&format!("user_{}", i)).await;
            assert!(result.is_some());
        }
    }

    #[tokio::test]
    async fn test_event_processor_with_timeout() {
        let (processor, handle) = EventProcessor::new();

        // Start processor in background
        let processor_task = tokio::spawn(handle.run());

        // Send test events
        let event = SystemEvent::UserRegistered {
            user_id: "test-user".to_string(),
            timestamp: Utc::now(),
        };

        processor.send_event(event).unwrap();

        // Test with timeout to prevent hanging
        let result = timeout(Duration::from_secs(5), async {
            // Give processor time to handle event
            tokio::time::sleep(Duration::from_millis(100)).await;
        }).await;

        assert!(result.is_ok());

        // Cleanup
        drop(processor);
        let _ = timeout(Duration::from_secs(1), processor_task).await;
    }
}
```

## 🚨 CONCURRENCY ANTI-PATTERNS

### What to Avoid
```rust
// ❌ Don't use std::sync in async contexts
// use std::sync::{Mutex, RwLock};
//
// struct BadAsyncCache {
//     data: std::sync::RwLock<HashMap<String, Value>>,  // Blocks async runtime
// }

// ❌ Don't use parking_lot in async code
// use parking_lot::{RwLock, Mutex};
//
// struct AlsoBadAsyncCache {
//     data: parking_lot::RwLock<HashMap<String, Value>>,  // Also blocks
// }

// ❌ Don't use Mutex<HashMap> for concurrent collections
// struct BadRegistry {
//     data: Arc<Mutex<HashMap<String, Value>>>,  // Use DashMap instead
// }

// ❌ Don't forget to handle cancellation in long-running tasks
// tokio::spawn(async {
//     loop {
//         // This loop never checks for cancellation
//         process_data().await;
//     }
// });

// ❌ Don't block the async runtime
// async fn bad_function() {
//     std::thread::sleep(Duration::from_secs(1));  // Blocks entire runtime
// }
```

## ✅ CONCURRENCY CHECKLIST

```markdown
### Concurrency Implementation Verification
- [ ] Uses tokio::sync primitives (not std::sync or parking_lot)
- [ ] DashMap used for concurrent collections instead of Mutex<HashMap>
- [ ] All long-running tasks support cancellation
- [ ] No blocking operations in async contexts
- [ ] Proper error handling in concurrent code
- [ ] Graceful shutdown implemented
- [ ] Tests include concurrent access scenarios
- [ ] Structured concurrency with JoinSet for parallel tasks
- [ ] Appropriate channel types used (mpsc, broadcast, oneshot)
- [ ] All async functions properly awaited
- [ ] No unwrap/expect in concurrent code
- [ ] Timeouts used for potentially hanging operations
```

This concurrency standard ensures safe, efficient, and maintainable concurrent Rust applications using modern async/await patterns.

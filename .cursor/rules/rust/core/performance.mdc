---
description:
globs:
alwaysApply: false
---
# ⚡ RUST PERFORMANCE OPTIMIZATION

> **TL;DR:** Performance optimization strategies for Rust applications, focusing on zero-cost abstractions, memory management, and profiling-driven optimization.

## 🔍 PERFORMANCE OPTIMIZATION STRATEGY

```mermaid
graph TD
    Start["Performance Issue"] --> Measure["Profile & Measure"]

    Measure --> Bottleneck{"Bottleneck<br>Type?"}

    Bottleneck -->|CPU| CPUOpt["CPU Optimization"]
    Bottleneck -->|Memory| MemOpt["Memory Optimization"]
    Bottleneck -->|I/O| IOOpt["I/O Optimization"]
    Bottleneck -->|Concurrency| ConcOpt["Concurrency Optimization"]

    CPUOpt --> SIMD["SIMD Vectorization"]
    CPUOpt --> Algorithms["Algorithm Optimization"]
    CPUOpt --> CompileTime["Compile-Time Optimization"]

    MemOpt --> Allocation["Allocation Strategy"]
    MemOpt --> DataStructure["Data Structure Choice"]
    MemOpt --> Caching["Caching Patterns"]

    IOOpt --> Buffering["Buffering Strategy"]
    IOOpt --> AsyncIO["Async I/O Patterns"]
    IOOpt --> Batching["Request Batching"]

    ConcOpt --> Parallelism["Parallel Processing"]
    ConcOpt --> Channels["Channel Optimization"]
    ConcOpt --> LockFree["Lock-Free Structures"]

    SIMD --> Verify["Benchmark & Verify"]
    Algorithms --> Verify
    CompileTime --> Verify
    Allocation --> Verify
    DataStructure --> Verify
    Caching --> Verify
    Buffering --> Verify
    AsyncIO --> Verify
    Batching --> Verify
    Parallelism --> Verify
    Channels --> Verify
    LockFree --> Verify

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style Measure fill:#ffa64d,stroke:#cc7a30,color:white
    style CPUOpt fill:#4dbb5f,stroke:#36873f,color:white
    style MemOpt fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 PERFORMANCE PRINCIPLES

### Measure First, Optimize Second
```rust
// ✅ Always profile before optimizing
use std::time::Instant;

#[cfg(feature = "profiling")]
macro_rules! time_it {
    ($name:expr, $block:block) => {{
        let start = Instant::now();
        let result = $block;
        let duration = start.elapsed();
        tracing::info!("{} took {:?}", $name, duration);
        result
    }};
}

#[cfg(not(feature = "profiling"))]
macro_rules! time_it {
    ($name:expr, $block:block) => {
        $block
    };
}

// Usage
fn process_data(data: &[u8]) -> Vec<u8> {
    time_it!("process_data", {
        // Expensive computation here
        data.iter().map(|&b| b.wrapping_mul(2)).collect()
    })
}
```

## 🏗️ MEMORY OPTIMIZATION

### String and Allocation Management
```rust
use std::borrow::Cow;

// ✅ Use Cow for flexible string handling
pub fn process_text<'a>(input: &'a str) -> Cow<'a, str> {
    if input.contains("old") {
        Cow::Owned(input.replace("old", "new"))
    } else {
        Cow::Borrowed(input)
    }
}

// ✅ Pre-allocate with known capacity
pub fn build_large_string(items: &[&str]) -> String {
    let total_len = items.iter().map(|s| s.len()).sum::<usize>();
    let mut result = String::with_capacity(total_len + items.len() - 1);

    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            result.push(' ');
        }
        result.push_str(item);
    }
    result
}

// ✅ Use Vec::with_capacity for known sizes
pub fn process_numbers(count: usize) -> Vec<i32> {
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        result.push(i as i32 * 2);
    }
    result
}

// ❌ Avoid repeated allocations
// fn bad_string_building(items: &[&str]) -> String {
//     let mut result = String::new();
//     for item in items {
//         result = result + item + " ";  // New allocation each time
//     }
//     result
// }
```

### Smart Pointer Optimization
```rust
use std::rc::Rc;
use std::sync::Arc;

// ✅ Use Rc for single-threaded shared ownership
#[derive(Debug, Clone)]
pub struct ConfigManager {
    config: Rc<Config>,
}

impl ConfigManager {
    pub fn new(config: Config) -> Self {
        Self {
            config: Rc::new(config),
        }
    }

    // Cheap to clone - only increments reference count
    pub fn get_config(&self) -> Rc<Config> {
        self.config.clone()
    }
}

// ✅ Use Arc for multi-threaded scenarios
#[derive(Debug, Clone)]
pub struct ThreadSafeCache {
    data: Arc<DashMap<String, Vec<u8>>>,
}

// ✅ Pool expensive objects
pub struct ConnectionPool {
    connections: Vec<DatabaseConnection>,
    available: std::collections::VecDeque<usize>,
}

impl ConnectionPool {
    pub async fn get_connection(&mut self) -> Option<PooledConnection> {
        if let Some(index) = self.available.pop_front() {
            Some(PooledConnection {
                connection: &mut self.connections[index],
                pool_index: index,
            })
        } else {
            None
        }
    }
}
```

## 🔄 ITERATION OPTIMIZATION

### Iterator Patterns
```rust
// ✅ Chain iterators for efficiency
pub fn process_and_filter(data: &[i32]) -> Vec<i32> {
    data.iter()
        .filter(|&&x| x > 0)
        .map(|&x| x * 2)
        .filter(|&x| x < 1000)
        .collect()
}

// ✅ Use fold for accumulation
pub fn sum_of_squares(numbers: &[i32]) -> i64 {
    numbers
        .iter()
        .map(|&x| x as i64)
        .map(|x| x * x)
        .fold(0, |acc, x| acc + x)
}

// ✅ Parallel iteration with rayon
use rayon::prelude::*;

pub fn parallel_process(data: &[f64]) -> Vec<f64> {
    data.par_iter()
        .map(|&x| expensive_computation(x))
        .collect()
}

fn expensive_computation(x: f64) -> f64 {
    // CPU-intensive operation
    x.powi(3) + x.powi(2) + x + 1.0
}

// ❌ Avoid collecting intermediate results
// fn inefficient_processing(data: &[i32]) -> Vec<i32> {
//     let filtered: Vec<_> = data.iter().filter(|&&x| x > 0).collect();
//     let mapped: Vec<_> = filtered.iter().map(|&x| x * 2).collect();
//     mapped.into_iter().filter(|&x| x < 1000).collect()
// }
```

### Custom Iterator Implementation
```rust
// ✅ Implement efficient custom iterators
pub struct ChunkIterator<'a, T> {
    data: &'a [T],
    chunk_size: usize,
    position: usize,
}

impl<'a, T> ChunkIterator<'a, T> {
    pub fn new(data: &'a [T], chunk_size: usize) -> Self {
        Self {
            data,
            chunk_size,
            position: 0,
        }
    }
}

impl<'a, T> Iterator for ChunkIterator<'a, T> {
    type Item = &'a [T];

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.data.len() {
            return None;
        }

        let end = std::cmp::min(self.position + self.chunk_size, self.data.len());
        let chunk = &self.data[self.position..end];
        self.position = end;
        Some(chunk)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.data.len() - self.position + self.chunk_size - 1) / self.chunk_size;
        (remaining, Some(remaining))
    }
}

impl<'a, T> ExactSizeIterator for ChunkIterator<'a, T> {}
```

## 🧮 COMPUTATIONAL OPTIMIZATION

### Vectorization and SIMD
```rust
// ✅ Use SIMD when available
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

pub fn sum_f32_slice(values: &[f32]) -> f32 {
    if is_x86_feature_detected!("avx2") {
        unsafe { sum_f32_avx2(values) }
    } else {
        values.iter().sum()
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sum_f32_avx2(values: &[f32]) -> f32 {
    let mut sum = _mm256_setzero_ps();
    let chunks = values.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let v = _mm256_loadu_ps(chunk.as_ptr());
        sum = _mm256_add_ps(sum, v);
    }

    // Extract the sum from the vector
    let mut result = [0.0f32; 8];
    _mm256_storeu_ps(result.as_mut_ptr(), sum);
    let vector_sum: f32 = result.iter().sum();

    // Add remainder
    vector_sum + remainder.iter().sum::<f32>()
}
```

### Lookup Tables and Memoization
```rust
use std::collections::HashMap;

// ✅ Use lookup tables for expensive computations
pub struct FibonacciCalculator {
    cache: HashMap<u64, u64>,
}

impl FibonacciCalculator {
    pub fn new() -> Self {
        let mut cache = HashMap::new();
        cache.insert(0, 0);
        cache.insert(1, 1);
        Self { cache }
    }

    pub fn fibonacci(&mut self, n: u64) -> u64 {
        if let Some(&result) = self.cache.get(&n) {
            return result;
        }

        let result = self.fibonacci(n - 1) + self.fibonacci(n - 2);
        self.cache.insert(n, result);
        result
    }
}

// ✅ Pre-computed lookup tables
pub struct SinTable {
    table: Vec<f64>,
    resolution: f64,
}

impl SinTable {
    pub fn new(resolution: usize) -> Self {
        let table: Vec<f64> = (0..resolution)
            .map(|i| {
                let angle = (i as f64) * 2.0 * std::f64::consts::PI / (resolution as f64);
                angle.sin()
            })
            .collect();

        Self {
            table,
            resolution: resolution as f64,
        }
    }

    pub fn sin_approx(&self, angle: f64) -> f64 {
        let normalized = angle % (2.0 * std::f64::consts::PI);
        let index = (normalized * self.resolution / (2.0 * std::f64::consts::PI)) as usize;
        self.table[index.min(self.table.len() - 1)]
    }
}
```

## 🔧 ASYNC PERFORMANCE

### Async Optimization Patterns
```rust
use tokio::task::JoinSet;
use futures::future::{join_all, try_join_all};

// ✅ Batch async operations
pub async fn fetch_user_data_batch(user_ids: &[UserId]) -> Result<Vec<User>, ServiceError> {
    const BATCH_SIZE: usize = 50;

    let mut results = Vec::with_capacity(user_ids.len());

    for chunk in user_ids.chunks(BATCH_SIZE) {
        let futures = chunk.iter().map(|&id| fetch_user_data(id));
        let batch_results = try_join_all(futures).await?;
        results.extend(batch_results);
    }

    Ok(results)
}

// ✅ Use bounded channels to prevent memory issues
pub async fn process_stream_with_backpressure() -> Result<(), ProcessingError> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(100); // Bounded channel

    // Producer task
    tokio::spawn(async move {
        for i in 0..1000 {
            if tx.send(i).await.is_err() {
                break;
            }
            // Producer will block when channel is full
        }
    });

    // Consumer task
    while let Some(item) = rx.recv().await {
        process_item(item).await?;
    }

    Ok(())
}

// ✅ Optimize async task spawning
pub async fn parallel_processing_optimized(items: Vec<ProcessingItem>) -> Vec<ProcessedResult> {
    let mut join_set = JoinSet::new();
    let concurrency_limit = num_cpus::get();

    for chunk in items.chunks(items.len() / concurrency_limit + 1) {
        let chunk = chunk.to_vec();
        join_set.spawn(async move {
            chunk.into_iter().map(process_item_sync).collect::<Vec<_>>()
        });
    }

    let mut results = Vec::new();
    while let Some(result) = join_set.join_next().await {
        if let Ok(chunk_results) = result {
            results.extend(chunk_results);
        }
    }

    results
}
```

## 📊 PROFILING AND BENCHMARKING

### Benchmarking with Criterion
```rust
// Cargo.toml
// [dev-dependencies]
// criterion = { version = "0.5", features = ["html_reports"] }

#[cfg(test)]
mod benches {
    use super::*;
    use criterion::{black_box, criterion_group, criterion_main, Criterion};

    fn bench_string_concatenation(c: &mut Criterion) {
        let data = vec!["hello"; 1000];

        c.bench_function("string_concat_push", |b| {
            b.iter(|| {
                let mut result = String::new();
                for s in &data {
                    result.push_str(black_box(s));
                }
                result
            })
        });

        c.bench_function("string_concat_join", |b| {
            b.iter(|| data.join(""))
        });

        c.bench_function("string_concat_capacity", |b| {
            b.iter(|| {
                let mut result = String::with_capacity(data.len() * 5);
                for s in &data {
                    result.push_str(black_box(s));
                }
                result
            })
        });
    }

    criterion_group!(benches, bench_string_concatenation);
    criterion_main!(benches);
}
```

### Memory Profiling
```rust
// Use instruments on macOS or valgrind on Linux
#[cfg(feature = "profiling")]
pub fn memory_intensive_operation() {
    // Add memory tracking
    let start_memory = get_memory_usage();

    // Your operation here
    let result = expensive_operation();

    let end_memory = get_memory_usage();
    println!("Memory used: {} bytes", end_memory - start_memory);
}

#[cfg(feature = "profiling")]
fn get_memory_usage() -> usize {
    // Platform-specific memory usage detection
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(contents) = fs::read_to_string("/proc/self/status") {
            for line in contents.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        return kb.parse::<usize>().unwrap_or(0) * 1024;
                    }
                }
            }
        }
    }
    0
}
```

## 🚨 PERFORMANCE ANTI-PATTERNS

### What to Avoid
```rust
// ❌ Don't clone unnecessarily
// fn bad_function(data: Vec<String>) -> Vec<String> {
//     data.clone()  // Unnecessary clone
// }

// ✅ Take ownership or borrow
fn good_function(data: Vec<String>) -> Vec<String> {
    data  // Move ownership
}

// ❌ Don't use Vec when you need Set operations
// fn slow_contains(vec: &Vec<String>, item: &str) -> bool {
//     vec.iter().any(|s| s == item)  // O(n) lookup
// }

// ✅ Use appropriate data structures
use std::collections::HashSet;
fn fast_contains(set: &HashSet<String>, item: &str) -> bool {
    set.contains(item)  // O(1) lookup
}

// ❌ Don't collect unnecessarily
// fn wasteful_processing(data: &[i32]) -> i32 {
//     data.iter()
//         .filter(|&&x| x > 0)
//         .collect::<Vec<_>>()  // Unnecessary allocation
//         .iter()
//         .sum()
// }

// ✅ Chain operations
fn efficient_processing(data: &[i32]) -> i32 {
    data.iter()
        .filter(|&&x| x > 0)
        .sum()
}
```

## 🎯 COMPILE-TIME OPTIMIZATION

### Cargo.toml Optimizations
```toml
[profile.release]
lto = true                    # Link-time optimization
codegen-units = 1            # Better optimization at cost of compile time
panic = "abort"              # Smaller binary size
strip = true                 # Remove debug symbols

[profile.release-with-debug]
inherits = "release"
debug = true                 # Keep debug info for profiling

# CPU-specific optimizations
[profile.release]
rustflags = ["-C", "target-cpu=native"]
```

### Feature Gates for Performance
```rust
// Cargo.toml
// [features]
// simd = []
// parallel = ["rayon"]

#[cfg(feature = "simd")]
pub fn fast_sum(data: &[f32]) -> f32 {
    sum_f32_slice(data)
}

#[cfg(not(feature = "simd"))]
pub fn fast_sum(data: &[f32]) -> f32 {
    data.iter().sum()
}

#[cfg(feature = "parallel")]
pub fn parallel_map<T, U, F>(data: &[T], f: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(&T) -> U + Sync,
{
    use rayon::prelude::*;
    data.par_iter().map(f).collect()
}

#[cfg(not(feature = "parallel"))]
pub fn parallel_map<T, U, F>(data: &[T], f: F) -> Vec<U>
where
    F: Fn(&T) -> U,
{
    data.iter().map(f).collect()
}
```

## ✅ PERFORMANCE CHECKLIST

```markdown
### Performance Implementation Verification
- [ ] Profile before optimizing (use criterion for benchmarks)
- [ ] Pre-allocate collections with known capacity
- [ ] Use appropriate data structures (HashMap vs Vec for lookups)
- [ ] Leverage iterator chains instead of intermediate collections
- [ ] Consider parallel processing for CPU-intensive tasks
- [ ] Use Cow for flexible string handling
- [ ] Implement object pooling for expensive resources
- [ ] Use SIMD when appropriate and available
- [ ] Optimize async task spawning and batching
- [ ] Enable LTO and appropriate optimization flags
- [ ] Use bounded channels to prevent memory issues
- [ ] Implement memoization for expensive computations
- [ ] Choose between Arc/Rc based on threading needs
- [ ] Avoid unnecessary clones and allocations
- [ ] Use const generics for compile-time optimizations
```

This performance guide provides practical optimization strategies while maintaining Rust's safety guarantees and zero-cost abstraction principles.

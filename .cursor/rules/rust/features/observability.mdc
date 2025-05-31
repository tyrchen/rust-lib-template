---
description:
globs:
alwaysApply: false
---
# 📊 RUST OBSERVABILITY PATTERNS

> **TL;DR:** Comprehensive observability patterns for Rust applications, including lock-free metrics collection, distributed tracing, health checks, and monitoring integration.

## 🔍 OBSERVABILITY STRATEGY

```mermaid
graph TD
    Start["Observability Needs"] --> MetricsQ{"Metrics<br>Required?"}
    Start --> TracingQ{"Distributed<br>Tracing?"}
    Start --> HealthQ{"Health<br>Checks?"}

    MetricsQ -->|Yes| MetricsType{"Metrics<br>Type?"}
    MetricsType -->|Counters| Counters["Lock-free Counters"]
    MetricsType -->|Histograms| Histograms["Response Time Tracking"]
    MetricsType -->|Gauges| Gauges["Current State Metrics"]

    TracingQ -->|Yes| TracingType{"Tracing<br>Scope?"}
    TracingType -->|Application| AppTracing["Application Tracing"]
    TracingType -->|Distributed| DistTracing["Distributed Tracing"]

    HealthQ -->|Yes| HealthType{"Health Check<br>Type?"}
    HealthType -->|Simple| SimpleHealth["Basic Health Checks"]
    HealthType -->|Complex| ComplexHealth["Dependency Health Checks"]

    Counters --> Collection["Metrics Collection"]
    Histograms --> Collection
    Gauges --> Collection

    AppTracing --> TracingCollection["Trace Collection"]
    DistTracing --> TracingCollection

    SimpleHealth --> HealthCollection["Health Monitoring"]
    ComplexHealth --> HealthCollection

    Collection --> Export["Export & Integration"]
    TracingCollection --> Export
    HealthCollection --> Export

    Export --> Production["Production Observability"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style Counters fill:#4dbb5f,stroke:#36873f,color:white
    style AppTracing fill:#ffa64d,stroke:#cc7a30,color:white
    style SimpleHealth fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 METRICS COLLECTION PATTERNS

### Lock-Free Metrics for High Performance
```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use dashmap::DashMap;
use prometheus::{Counter, Histogram, Gauge, Registry, Opts, HistogramOpts};

// ✅ Lock-free atomic counter for high-throughput scenarios
#[derive(Debug)]
pub struct AtomicCounter {
    value: AtomicU64,
}

impl AtomicCounter {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn increment(&self) -> u64 {
        self.value.fetch_add(1, Ordering::Relaxed)
    }

    pub fn add(&self, value: u64) -> u64 {
        self.value.fetch_add(value, Ordering::Relaxed)
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::Relaxed)
    }
}

impl Default for AtomicCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ✅ Comprehensive metrics collector
pub struct MetricsCollector {
    counters: DashMap<String, Arc<AtomicCounter>>,
    prometheus_counters: DashMap<String, Counter>,
    prometheus_histograms: DashMap<String, Histogram>,
    prometheus_gauges: DashMap<String, Gauge>,
    registry: Registry,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
            prometheus_counters: DashMap::new(),
            prometheus_histograms: DashMap::new(),
            prometheus_gauges: DashMap::new(),
            registry: Registry::new(),
        }
    }

    /// Get or create a counter
    pub fn counter(&self, name: &str) -> Arc<AtomicCounter> {
        self.counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(AtomicCounter::new()))
            .clone()
    }

    /// Get or create a Prometheus counter
    pub fn prometheus_counter(&self, name: &str, help: &str) -> Result<Counter, MetricsError> {
        if let Some(counter) = self.prometheus_counters.get(name) {
            return Ok(counter.clone());
        }

        let opts = Opts::new(name, help);
        let counter = Counter::with_opts(opts)?;
        self.registry.register(Box::new(counter.clone()))?;
        self.prometheus_counters.insert(name.to_string(), counter.clone());

        Ok(counter)
    }

    /// Get or create a Prometheus histogram
    pub fn prometheus_histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Result<Histogram, MetricsError> {
        if let Some(histogram) = self.prometheus_histograms.get(name) {
            return Ok(histogram.clone());
        }

        let opts = HistogramOpts::new(name, help).buckets(buckets);
        let histogram = Histogram::with_opts(opts)?;
        self.registry.register(Box::new(histogram.clone()))?;
        self.prometheus_histograms.insert(name.to_string(), histogram.clone());

        Ok(histogram)
    }

    /// Get or create a Prometheus gauge
    pub fn prometheus_gauge(&self, name: &str, help: &str) -> Result<Gauge, MetricsError> {
        if let Some(gauge) = self.prometheus_gauges.get(name) {
            return Ok(gauge.clone());
        }

        let opts = Opts::new(name, help);
        let gauge = Gauge::with_opts(opts)?;
        self.registry.register(Box::new(gauge.clone()))?;
        self.prometheus_gauges.insert(name.to_string(), gauge.clone());

        Ok(gauge)
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> Result<String, MetricsError> {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();

        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;

        Ok(String::from_utf8(buffer)?)
    }

    /// Get all counter values as a snapshot
    pub fn counter_snapshot(&self) -> std::collections::HashMap<String, u64> {
        self.counters
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().get()))
            .collect()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
```

### Application Metrics Patterns
```rust
use std::time::{Duration, Instant};

// ✅ Request timing middleware pattern
pub struct RequestTimer {
    start_time: Instant,
    metrics: Arc<MetricsCollector>,
    operation: String,
}

impl RequestTimer {
    pub fn start(metrics: Arc<MetricsCollector>, operation: impl Into<String>) -> Self {
        let operation = operation.into();

        // Increment request counter
        metrics.counter(&format!("{}_requests_total", operation)).increment();

        Self {
            start_time: Instant::now(),
            metrics,
            operation,
        }
    }

    pub fn finish(self) -> Duration {
        let duration = self.start_time.elapsed();

        // Record timing histogram
        if let Ok(histogram) = self.metrics.prometheus_histogram(
            &format!("{}_duration_seconds", self.operation),
            &format!("Request duration for {}", self.operation),
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        ) {
            histogram.observe(duration.as_secs_f64());
        }

        duration
    }
}

// ✅ Metrics middleware for HTTP servers
#[derive(Clone)]
pub struct MetricsMiddleware {
    metrics: Arc<MetricsCollector>,
}

impl MetricsMiddleware {
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self { metrics }
    }

    pub async fn track_request<F, Fut, T>(&self, operation: &str, future: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let timer = RequestTimer::start(self.metrics.clone(), operation);
        let result = future().await;
        timer.finish();
        result
    }
}

// ✅ Business metrics collection
pub trait BusinessMetrics {
    fn record_user_registration(&self);
    fn record_user_login(&self);
    fn record_transaction(&self, amount: f64);
    fn record_error(&self, error_type: &str);
}

impl BusinessMetrics for MetricsCollector {
    fn record_user_registration(&self) {
        self.counter("user_registrations_total").increment();
    }

    fn record_user_login(&self) {
        self.counter("user_logins_total").increment();
    }

    fn record_transaction(&self, amount: f64) {
        self.counter("transactions_total").increment();

        if let Ok(histogram) = self.prometheus_histogram(
            "transaction_amounts",
            "Distribution of transaction amounts",
            vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0],
        ) {
            histogram.observe(amount);
        }
    }

    fn record_error(&self, error_type: &str) {
        self.counter(&format!("errors_total_{}", error_type)).increment();
    }
}
```

## 🔍 DISTRIBUTED TRACING PATTERNS

### OpenTelemetry Integration
```rust
use opentelemetry::global;
use opentelemetry::trace::{TraceId, SpanId, TraceContextExt, Tracer};
use opentelemetry::Context;
use tracing::{info_span, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

// ✅ Tracing configuration
pub struct TracingConfig {
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub jaeger_endpoint: Option<String>,
}

pub fn setup_tracing(config: TracingConfig) -> Result<(), TracingError> {
    use opentelemetry::sdk::trace;
    use opentelemetry::sdk::Resource;
    use opentelemetry::KeyValue;

    // Create resource with service information
    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name),
        KeyValue::new("service.version", config.service_version),
        KeyValue::new("environment", config.environment),
    ]);

    // Initialize tracer
    let tracer = if let Some(endpoint) = config.jaeger_endpoint {
        opentelemetry_jaeger::new_agent_pipeline()
            .with_endpoint(endpoint)
            .with_service_name("my-service")
            .install_simple()?
    } else {
        opentelemetry::sdk::trace::TracerProvider::builder()
            .with_config(trace::config().with_resource(resource))
            .build()
            .tracer("my-service")
    };

    // Initialize tracing subscriber
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(telemetry)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    Ok(())
}

// ✅ Tracing helper macros and functions
pub fn trace_async_fn<F, Fut, T>(span_name: &str, future: F) -> impl std::future::Future<Output = T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    async move {
        let span = info_span!("async_operation", operation = span_name);
        let _enter = span.enter();
        future().await
    }
}

// ✅ Distributed tracing context propagation
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub span_context: opentelemetry::trace::SpanContext,
}

impl TraceContext {
    pub fn current() -> Option<Self> {
        let context = Context::current();
        let span_context = context.span().span_context();

        if span_context.is_valid() {
            Some(Self {
                trace_id: span_context.trace_id(),
                span_id: span_context.span_id(),
                span_context: span_context.clone(),
            })
        } else {
            None
        }
    }

    pub fn to_headers(&self) -> std::collections::HashMap<String, String> {
        use opentelemetry::propagation::{Injector, TextMapPropagator};

        let mut headers = std::collections::HashMap::new();
        let propagator = opentelemetry_jaeger::Propagator::new();
        let context = Context::current_with_span(
            opentelemetry::trace::TraceContextExt::span(&Context::current())
        );

        propagator.inject_context(&context, &mut headers);
        headers
    }

    pub fn from_headers(headers: &std::collections::HashMap<String, String>) -> Context {
        use opentelemetry::propagation::{Extractor, TextMapPropagator};

        let propagator = opentelemetry_jaeger::Propagator::new();
        let context = propagator.extract(headers);
        context
    }
}

// ✅ Custom span attributes
pub trait SpanExtensions {
    fn with_user_id(self, user_id: &str) -> Self;
    fn with_request_id(self, request_id: &str) -> Self;
    fn with_operation_result(self, success: bool) -> Self;
}

impl SpanExtensions for Span {
    fn with_user_id(self, user_id: &str) -> Self {
        self.record("user.id", user_id);
        self
    }

    fn with_request_id(self, request_id: &str) -> Self {
        self.record("request.id", request_id);
        self
    }

    fn with_operation_result(self, success: bool) -> Self {
        self.record("operation.success", success);
        if !success {
            self.record("error", true);
        }
        self
    }
}
```

## 🏥 HEALTH CHECK PATTERNS

### Comprehensive Health Monitoring
```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ✅ Health check status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub message: String,
    pub details: HashMap<String, serde_json::Value>,
    pub duration: Duration,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl HealthCheckResult {
    pub fn healthy(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: message.into(),
            details: HashMap::new(),
            duration: Duration::from_millis(0),
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Degraded,
            message: message.into(),
            details: HashMap::new(),
            duration: Duration::from_millis(0),
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            message: message.into(),
            details: HashMap::new(),
            duration: Duration::from_millis(0),
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.details.insert(key.into(), value);
        self
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
}

// ✅ Health check trait
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    async fn check(&self) -> HealthCheckResult;
    fn name(&self) -> &str;
    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

// ✅ Database health check implementation
pub struct DatabaseHealthCheck {
    pool: sqlx::PgPool,
    name: String,
}

impl DatabaseHealthCheck {
    pub fn new(pool: sqlx::PgPool, name: impl Into<String>) -> Self {
        Self {
            pool,
            name: name.into(),
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for DatabaseHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let start = std::time::Instant::now();

        match sqlx::query("SELECT 1").fetch_one(&self.pool).await {
            Ok(_) => {
                let duration = start.elapsed();
                HealthCheckResult::healthy("Database connection successful")
                    .with_duration(duration)
                    .with_detail("query_time_ms", (duration.as_millis() as f64).into())
            }
            Err(e) => {
                let duration = start.elapsed();
                HealthCheckResult::unhealthy(format!("Database connection failed: {}", e))
                    .with_duration(duration)
                    .with_detail("error", e.to_string().into())
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
}

// ✅ Health check manager
pub struct HealthManager {
    checks: HashMap<String, Box<dyn HealthCheck>>,
}

impl HealthManager {
    pub fn new() -> Self {
        Self {
            checks: HashMap::new(),
        }
    }

    pub fn add_check(&mut self, check: Box<dyn HealthCheck>) {
        let name = check.name().to_string();
        self.checks.insert(name, check);
    }

    pub async fn check_all(&self) -> HashMap<String, HealthCheckResult> {
        let mut results = HashMap::new();

        for (name, check) in &self.checks {
            let timeout = check.timeout();

            let result = match tokio::time::timeout(timeout, check.check()).await {
                Ok(result) => result,
                Err(_) => HealthCheckResult::unhealthy(format!("Health check timed out after {:?}", timeout))
                    .with_detail("timeout", timeout.as_secs().into()),
            };

            results.insert(name.clone(), result);
        }

        results
    }

    pub async fn overall_status(&self) -> HealthStatus {
        let results = self.check_all().await;

        let mut has_degraded = false;

        for result in results.values() {
            match result.status {
                HealthStatus::Unhealthy => return HealthStatus::Unhealthy,
                HealthStatus::Degraded => has_degraded = true,
                HealthStatus::Healthy => {}
            }
        }

        if has_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }
}

impl Default for HealthManager {
    fn default() -> Self {
        Self::new()
    }
}
```

## 🚨 ERROR HANDLING FOR OBSERVABILITY

### Observability Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    #[error("Prometheus error: {0}")]
    Prometheus(#[from] prometheus::Error),

    #[error("UTF-8 encoding error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Metrics collection failed: {0}")]
    Collection(String),
}

#[derive(Debug, thiserror::Error)]
pub enum TracingError {
    #[error("OpenTelemetry error: {0}")]
    OpenTelemetry(#[from] opentelemetry::trace::TraceError),

    #[error("Jaeger error: {0}")]
    Jaeger(String),

    #[error("Tracing setup failed: {0}")]
    Setup(String),
}

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("Health check failed: {0}")]
    CheckFailed(String),

    #[error("Health check timeout: {0}")]
    Timeout(String),

    #[error("Health manager error: {0}")]
    Manager(String),
}
```

## 🧪 OBSERVABILITY TESTING

### Testing Patterns
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_atomic_counter() {
        let counter = AtomicCounter::new();
        assert_eq!(counter.get(), 0);

        counter.increment();
        assert_eq!(counter.get(), 1);

        counter.add(5);
        assert_eq!(counter.get(), 6);

        let old_value = counter.reset();
        assert_eq!(old_value, 6);
        assert_eq!(counter.get(), 0);
    }

    #[tokio::test]
    async fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        // Test counter creation and increment
        let counter = collector.counter("test_requests");
        counter.increment();
        counter.add(5);

        let snapshot = collector.counter_snapshot();
        assert_eq!(snapshot.get("test_requests"), Some(&6));
    }

    #[tokio::test]
    async fn test_request_timer() {
        let metrics = Arc::new(MetricsCollector::new());
        let timer = RequestTimer::start(metrics.clone(), "test_operation");

        // Simulate some work
        tokio::time::sleep(Duration::from_millis(10)).await;

        let duration = timer.finish();
        assert!(duration >= Duration::from_millis(10));

        // Check that counter was incremented
        let snapshot = metrics.counter_snapshot();
        assert_eq!(snapshot.get("test_operation_requests_total"), Some(&1));
    }

    #[tokio::test]
    async fn test_health_check() {
        struct MockHealthCheck {
            should_pass: bool,
        }

        #[async_trait::async_trait]
        impl HealthCheck for MockHealthCheck {
            async fn check(&self) -> HealthCheckResult {
                if self.should_pass {
                    HealthCheckResult::healthy("Mock check passed")
                } else {
                    HealthCheckResult::unhealthy("Mock check failed")
                }
            }

            fn name(&self) -> &str {
                "mock_check"
            }
        }

        let mut manager = HealthManager::new();
        manager.add_check(Box::new(MockHealthCheck { should_pass: true }));

        let results = manager.check_all().await;
        assert_eq!(results.len(), 1);
        assert_eq!(results["mock_check"].status, HealthStatus::Healthy);

        let overall = manager.overall_status().await;
        assert_eq!(overall, HealthStatus::Healthy);
    }
}
```

## ✅ OBSERVABILITY CHECKLIST

```markdown
### Observability Implementation Verification
- [ ] Lock-free metrics collection implemented
- [ ] Prometheus metrics integration working
- [ ] Request timing and duration tracking
- [ ] Business metrics collection in place
- [ ] Distributed tracing configured
- [ ] Trace context propagation working
- [ ] Custom span attributes defined
- [ ] Health checks for all dependencies
- [ ] Health check timeout handling
- [ ] Overall health status aggregation
- [ ] Metrics export endpoints exposed
- [ ] Error metrics collection
- [ ] Performance impact minimized
- [ ] Testing coverage for all components
- [ ] Documentation for metrics and traces
```

This observability guide provides comprehensive patterns for monitoring, tracing, and health checking in production Rust applications.

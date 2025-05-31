---
description:
globs:
alwaysApply: false
---
# 🏢 MULTI-CRATE WORKSPACE STRUCTURE

> **TL;DR:** Guidelines for organizing complex Rust projects using workspace architecture with multiple crates, clear subsystem boundaries, and domain-driven design principles.

## 🔍 WORKSPACE ARCHITECTURE STRATEGY

```mermaid
graph TD
    Start["Complex Project"] --> ArchType{"Architecture<br>Pattern?"}

    ArchType -->|Domain-Driven| DomainArch["Domain-Based Architecture"]
    ArchType -->|Service-Oriented| ServiceArch["Service-Based Architecture"]
    ArchType -->|Layered| LayeredArch["Layered Architecture"]

    DomainArch --> DomainCrates["Domain-Specific Crates"]
    ServiceArch --> ServiceCrates["Service-Specific Crates"]
    LayeredArch --> LayerCrates["Layer-Specific Crates"]

    DomainCrates --> SharedInfra["Shared Infrastructure"]
    ServiceCrates --> SharedInfra
    LayerCrates --> SharedInfra

    SharedInfra --> WorkspaceDeps["Workspace Dependencies"]
    WorkspaceDeps --> CrateOrganization["Crate Organization"]

    CrateOrganization --> IntegrationTesting["Integration Testing"]
    IntegrationTesting --> BuildOptimization["Build Optimization"]
    BuildOptimization --> Documentation["Workspace Documentation"]

    Documentation --> Production["Production Workspace"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style DomainArch fill:#4dbb5f,stroke:#36873f,color:white
    style ServiceArch fill:#ffa64d,stroke:#cc7a30,color:white
    style LayeredArch fill:#d94dbb,stroke:#a3378a,color:white
```

## 🏗️ SERVICE-ORIENTED WORKSPACE ARCHITECTURE

```mermaid
graph TD
    Workspace["Service Platform Workspace"] --> Shared["Shared Infrastructure"]
    Workspace --> CoreServices["Core Services"]
    Workspace --> BusinessServices["Business Services"]
    Workspace --> PlatformServices["Platform Services"]

    Shared --> SharedTypes["shared-types<br/>(domain primitives)"]
    Shared --> SharedConfig["shared-config<br/>(configuration)"]
    Shared --> SharedObservability["shared-observability<br/>(metrics & tracing)"]

    CoreServices --> ServiceCore["service-core<br/>(business logic)"]
    CoreServices --> ServiceApi["service-api<br/>(HTTP handlers)"]
    CoreServices --> ServiceWorker["service-worker<br/>(background jobs)"]

    BusinessServices --> BusinessCore["business-core<br/>(domain logic)"]
    BusinessServices --> BusinessApi["business-api<br/>(API endpoints)"]
    BusinessServices --> BusinessProcessor["business-processor<br/>(workflow engine)"]

    PlatformServices --> Gateway["gateway<br/>(API gateway)"]
    PlatformServices --> AdminPanel["admin-panel<br/>(administration)"]
    PlatformServices --> HealthMonitor["health-monitor<br/>(monitoring)"]

    style Workspace fill:#4da6ff,stroke:#0066cc,color:white
    style Shared fill:#4dbb5f,stroke:#36873f,color:white
    style CoreServices fill:#ffa64d,stroke:#cc7a30,color:white
    style BusinessServices fill:#d94dbb,stroke:#a3378a,color:white
    style PlatformServices fill:#9b59b6,stroke:#7d4796,color:white
```

## 🔄 SERVICE CONFIGURATION MANAGEMENT

### Hot-Reloadable Service Architecture
```rust
use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::sync::broadcast;

// ✅ Service-oriented architecture with shared state
pub struct ServiceManager<T> {
    config: Arc<ArcSwap<T>>,
    components: Vec<Arc<dyn ServiceComponent>>,
    config_tx: broadcast::Sender<Arc<T>>,
}

impl<T> ServiceManager<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn new(initial_config: T) -> Self {
        let (config_tx, _) = broadcast::channel(16);

        Self {
            config: Arc::new(ArcSwap::from_pointee(initial_config)),
            components: Vec::new(),
            config_tx,
        }
    }

    pub fn add_component(&mut self, component: Arc<dyn ServiceComponent>) {
        self.components.push(component);
    }

    pub fn update_config(&self, new_config: T) {
        let new_config = Arc::new(new_config);
        self.config.store(new_config.clone());

        // Notify all components of config change
        for component in &self.components {
            component.on_config_update();
        }

        // Broadcast to subscribers
        let _ = self.config_tx.send(new_config);
    }

    pub fn get_config(&self) -> Arc<T> {
        self.config.load_full()
    }

    pub fn subscribe_to_config_changes(&self) -> broadcast::Receiver<Arc<T>> {
        self.config_tx.subscribe()
    }
}

pub trait ServiceComponent: Send + Sync {
    fn on_config_update(&self);
    fn service_name(&self) -> &str;
    fn health_check(&self) -> ServiceHealth;
}

#[derive(Debug, Clone)]
pub enum ServiceHealth {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
}
```

## 📁 SERVICE-ORIENTED DIRECTORY STRUCTURE

```
service-platform/
├── Cargo.toml                 # Workspace configuration
├── Cargo.lock                 # Locked dependencies
├── README.md                   # Platform overview
├── docker-compose.yml         # Development environment
├── .env.example               # Environment template
├──
├── shared/                    # Cross-cutting infrastructure
│   ├── shared-types/          # Domain primitives & common types
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ids.rs         # EntityId, RequestId types
│   │       ├── time.rs        # Timestamp, Duration types
│   │       ├── pagination.rs  # Pagination, Sorting types
│   │       └── validation.rs  # Common validation rules
│   │
│   ├── shared-config/         # Configuration management
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── service.rs     # Service configuration
│   │       ├── database.rs    # Database configuration
│   │       ├── observability.rs # Metrics & tracing config
│   │       └── environment.rs # Environment-specific settings
│   │
│   └── shared-observability/  # Metrics & tracing infrastructure
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── metrics.rs     # Metrics collection patterns
│           ├── tracing.rs     # Distributed tracing setup
│           ├── health.rs      # Health check framework
│           └── middleware.rs  # Observability middleware
│
├── services/                  # Business services
│   ├── core-services/         # Core business logic services
│   │   ├── service-core/      # Core business logic
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs
│   │   │       ├── entities/    # Core domain entities
│   │   │       ├── services/    # Business service implementations
│   │   │       ├── repositories/ # Repository trait definitions
│   │   │       └── errors.rs
│   │   │
│   │   ├── service-api/       # HTTP API handlers
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs
│   │   │       ├── handlers/    # HTTP endpoint handlers
│   │   │       ├── middleware/  # API middleware
│   │   │       ├── dto/        # Request/response DTOs
│   │   │       └── validation.rs
│   │   │
│   │   └── service-worker/    # Background processing
│   │       ├── Cargo.toml
│   │       └── src/
│   │           ├── main.rs
│   │           ├── jobs/       # Background job definitions
│   │           └── processors.rs
│   │
│   ├── business-services/     # Business-specific services
│   │   ├── business-core/     # Business domain logic
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs
│   │   │       ├── entities/    # Business domain entities
│   │   │       ├── services/    # Business logic services
│   │   │       ├── workflows/   # Business process workflows
│   │   │       └── errors.rs
│   │   │
│   │   ├── business-api/      # Business API endpoints
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs
│   │   │       ├── handlers/    # Business endpoint handlers
│   │   │       ├── dto/        # Business DTOs
│   │   │       └── validators.rs
│   │   │
│   │   └── business-processor/ # Business workflow engine
│   │       ├── Cargo.toml
│   │       └── src/
│   │           ├── lib.rs
│   │           ├── workflows/   # Workflow definitions
│   │           ├── steps/       # Workflow step implementations
│   │           └── executor.rs  # Workflow execution engine
│   │   │       ├── services/    # OrderService, CartService
│   │   │       ├── state_machine/ # Order state transitions
│   │   │       ├── repositories/
│   │   │       └── errors.rs
│   │   │
│   │   ├── order-api/         # HTTP API handlers
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs
│   │   │       ├── handlers/    # Cart, checkout, order status
│   │   │       ├── dto/
│   │   │       └── validation.rs
│   │   │
│   │   └── order-processor/   # Order workflow engine
│   │       ├── Cargo.toml
│   │       └── src/
│   │           ├── main.rs
│   │           ├── workflows/   # Order fulfillment workflow
│   │           ├── tasks/      # Individual processing tasks
│   │           └── scheduler.rs
│   │
│   ├── payment/               # Payment processing subsystem
│   │   ├── payment-core/      # Business logic
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs
│   │   │       ├── entities/    # Payment, Transaction, Refund
│   │   │       ├── services/    # PaymentService, RefundService
│   │   │       ├── state_machine/ # Payment state transitions
│   │   │       ├── repositories/
│   │   │       └── errors.rs
│   │   │
│   │   ├── payment-api/       # HTTP API handlers
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs
│   │   │       ├── handlers/    # Payment endpoints
│   │   │       ├── webhooks/   # Payment gateway webhooks
│   │   │       ├── dto/
│   │   │       └── security.rs  # Payment security
│   │   │
│   │   └── payment-gateway/   # External payment integrations
│   │       ├── Cargo.toml
│   │       └── src/
│   │           ├── lib.rs
│   │           ├── stripe/     # Stripe integration
│   │           ├── paypal/     # PayPal integration
│   │           ├── providers/  # Payment provider traits
│   │           └── encryption.rs
│   │
│   ├── notification/          # Notification subsystem
│   │   ├── notification-core/ # Business logic
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs
│   │   │       ├── entities/    # Notification, Template
│   │   │       ├── services/    # NotificationService
│   │   │       ├── templates/   # Email/SMS templates
│   │   │       ├── repositories/
│   │   │       └── errors.rs
│   │   │
│   │   └── notification-service/ # Notification delivery
│   │       ├── Cargo.toml
│   │       └── src/
│   │           ├── main.rs
│   │           ├── channels/    # Email, SMS, Push delivery
│   │           ├── queue/      # Message queue integration
│   │           ├── templates/  # Template rendering
│   │           └── retry.rs    # Delivery retry logic
│   │
│   └── analytics/             # Analytics & reporting subsystem
│       ├── analytics-core/    # Business logic
│       │   ├── Cargo.toml
│       │   └── src/
│       │       ├── lib.rs
│       │       ├── entities/    # Metric, Report, Dashboard
│       │       ├── services/    # AnalyticsService, ReportService
│       │       ├── aggregators/ # Data aggregation logic
│       │       ├── repositories/
│       │       └── errors.rs
│       │
│       ├── analytics-collector/ # Data collection service
│       │   ├── Cargo.toml
│       │   └── src/
│       │       ├── main.rs
│       │       ├── collectors/  # Event collectors
│       │       ├── processors/ # Data processing pipelines
│       │       └── storage.rs  # Time-series data storage
│       │
│       └── analytics-reporter/ # Reporting service
│           ├── Cargo.toml
│           └── src/
│               ├── main.rs
│               ├── generators/ # Report generators
│               ├── schedulers/ # Scheduled reporting
│               └── exporters/  # Report export formats
│
└── services/                  # Infrastructure & gateway services
    ├── api-gateway/          # Unified API gateway
    │   ├── Cargo.toml
    │   └── src/
    │       ├── main.rs
    │       ├── routing/       # Request routing
    │       ├── middleware/    # CORS, rate limiting, auth
    │       ├── load_balancer/ # Load balancing logic
    │       └── monitoring.rs  # Health checks, metrics
    │
    ├── admin-cli/            # Administrative CLI tool
    │   ├── Cargo.toml
    │   └── src/
    │       ├── main.rs
    │       ├── commands/      # Admin commands
    │       ├── scripts/       # Automation scripts
    │       └── monitoring.rs  # System monitoring
    │
    └── migration-tool/       # Database migration tool
        ├── Cargo.toml
        └── src/
            ├── main.rs
            ├── migrations/    # SQL migration files
            ├── schemas/       # Database schemas
            └── validation.rs  # Migration validation
```

## 🔧 SUBSYSTEM-BASED WORKSPACE CARGO.TOML

```toml
[workspace]
resolver = "2"
members = [
    # Shared infrastructure
    "shared/shared-types",
    "shared/shared-db",
    "shared/shared-config",
    "shared/shared-events",

    # User Management Subsystem
    "subsystems/user-management/user-core",
    "subsystems/user-management/user-api",
    "subsystems/user-management/user-worker",

    # Product Catalog Subsystem
    "subsystems/product-catalog/product-core",
    "subsystems/product-catalog/product-api",
    "subsystems/product-catalog/product-search",

    # Order Management Subsystem
    "subsystems/order-management/order-core",
    "subsystems/order-management/order-api",
    "subsystems/order-management/order-processor",

    # Payment Subsystem
    "subsystems/payment/payment-core",
    "subsystems/payment/payment-api",
    "subsystems/payment/payment-gateway",

    # Notification Subsystem
    "subsystems/notification/notification-core",
    "subsystems/notification/notification-service",

    # Analytics Subsystem
    "subsystems/analytics/analytics-core",
    "subsystems/analytics/analytics-collector",
    "subsystems/analytics/analytics-reporter",

    # Infrastructure Services
    "services/api-gateway",
    "services/admin-cli",
    "services/migration-tool",
]

# Shared dependencies across workspace
[workspace.dependencies]
# Core dependencies
anyhow = "1.0"
thiserror = "2.0"
derive_more = { version = "2.0", features = ["constructor", "display", "error", "from"] }
typed-builder = "0.21"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"

# Async runtime
tokio = { version = "1.45", features = ["macros", "rt-multi-thread", "net", "fs", "time", "sync", "signal"] }
async-trait = "0.1"
futures = "0.3"

# Web framework
axum = { version = "0.8", features = ["macros", "multipart"] }
tower = { version = "0.5", features = ["full"] }
tower-http = { version = "0.6", features = ["cors", "trace", "compression", "auth", "limit"] }
http = "1.0"

# API documentation
utoipa = { version = "5.0", features = ["axum_extras", "chrono", "uuid"] }
utoipa-axum = "0.2"
utoipa-swagger-ui = { version = "9.0", features = ["axum"] }

# Database
sqlx = { version = "0.8", features = [
    "runtime-tokio-rustls",
    "postgres",
    "sqlite",
    "chrono",
    "uuid",
    "time",
    "json"
] }

# HTTP client
reqwest = { version = "0.12", features = ["rustls-tls", "json", "stream", "multipart"] }

# Time handling
chrono = { version = "0.4", features = ["serde"] }
time = { version = "0.3", features = ["serde"] }

# Unique identifiers
uuid = { version = "1.17", features = ["v4", "v7", "serde"] }

# Concurrent data structures
dashmap = "6.0"

# Configuration
arc-swap = "1.0"

# Templating
minijinja = { version = "2.0", features = ["loader", "json", "custom_syntax"] }

# Authentication
jsonwebtoken = "9.0"

# Utilities
base64 = "0.22"
regex = "1.0"
rand = { version = "0.8", features = ["std_rng"] }
getrandom = { version = "0.3", features = ["std"] }

# CLI
clap = { version = "4.0", features = ["derive", "env"] }

# Logging and tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json", "chrono"] }

# Testing
tempfile = "3.0"
wiremock = "0.6"

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["Platform Team <platform@company.com>"]
license = "MIT OR Apache-2.0"
repository = "https://github.com/company/ecommerce-platform"

# Performance optimizations
[profile.release]
lto = true
codegen-units = 1
panic = "abort"

[profile.dev]
debug = true
opt-level = 0

# Shared linting configuration
[workspace.lints.rust]
unused_must_use = "warn"
unsafe_code = "forbid"
missing_docs = "warn"

[workspace.lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
cargo = "warn"
# Allow some pedantic lints that are too strict
module_name_repetitions = "allow"
must_use_candidate = "allow"
```

## 🏗️ SUBSYSTEM DEPENDENCY ARCHITECTURE

```mermaid
graph TD
    subgraph "Gateway Layer"
        ApiGateway["api-gateway"]
        AdminCli["admin-cli"]
        MigrationTool["migration-tool"]
    end

    subgraph "Application Layer"
        UserApi["user-api"]
        ProductApi["product-api"]
        OrderApi["order-api"]
        PaymentApi["payment-api"]

        UserWorker["user-worker"]
        OrderProcessor["order-processor"]
        NotificationService["notification-service"]
        AnalyticsCollector["analytics-collector"]
        AnalyticsReporter["analytics-reporter"]
    end

    subgraph "Domain Layer"
        UserCore["user-core"]
        ProductCore["product-core"]
        OrderCore["order-core"]
        PaymentCore["payment-core"]
        NotificationCore["notification-core"]
        AnalyticsCore["analytics-core"]

        ProductSearch["product-search"]
        PaymentGateway["payment-gateway"]
    end

    subgraph "Infrastructure Layer"
        SharedTypes["shared-types"]
        SharedDb["shared-db"]
        SharedConfig["shared-config"]
        SharedEvents["shared-events"]
    end

    %% Gateway dependencies
    ApiGateway --> UserApi
    ApiGateway --> ProductApi
    ApiGateway --> OrderApi
    ApiGateway --> PaymentApi

    AdminCli --> UserCore
    AdminCli --> ProductCore
    AdminCli --> OrderCore
    AdminCli --> SharedDb

    MigrationTool --> SharedDb

    %% Application layer dependencies
    UserApi --> UserCore
    ProductApi --> ProductCore
    ProductApi --> ProductSearch
    OrderApi --> OrderCore
    PaymentApi --> PaymentCore

    UserWorker --> UserCore
    OrderProcessor --> OrderCore
    OrderProcessor --> PaymentCore
    NotificationService --> NotificationCore
    AnalyticsCollector --> AnalyticsCore
    AnalyticsReporter --> AnalyticsCore

    %% Domain layer dependencies
    UserCore --> SharedTypes
    UserCore --> SharedDb
    UserCore --> SharedEvents

    ProductCore --> SharedTypes
    ProductCore --> SharedDb
    ProductCore --> SharedEvents

    OrderCore --> SharedTypes
    OrderCore --> SharedDb
    OrderCore --> SharedEvents
    OrderCore --> UserCore
    OrderCore --> ProductCore

    PaymentCore --> SharedTypes
    PaymentCore --> SharedDb
    PaymentCore --> SharedEvents
    PaymentCore --> OrderCore

    NotificationCore --> SharedTypes
    NotificationCore --> SharedDb
    NotificationCore --> SharedEvents

    AnalyticsCore --> SharedTypes
    AnalyticsCore --> SharedDb

    ProductSearch --> ProductCore
    PaymentGateway --> PaymentCore

    %% Infrastructure dependencies
    SharedDb --> SharedConfig
    SharedEvents --> SharedTypes

    style ApiGateway fill:#2ecc71,stroke:#27ae60,color:white
    style AdminCli fill:#2ecc71,stroke:#27ae60,color:white
    style MigrationTool fill:#2ecc71,stroke:#27ae60,color:white

    style UserApi fill:#ffa64d,stroke:#cc7a30,color:white
    style ProductApi fill:#d94dbb,stroke:#a3378a,color:white
    style OrderApi fill:#4dbbbb,stroke:#368787,color:white
    style PaymentApi fill:#ff6b6b,stroke:#cc5555,color:white
    style UserWorker fill:#ffa64d,stroke:#cc7a30,color:white
    style OrderProcessor fill:#4dbbbb,stroke:#368787,color:white
    style NotificationService fill:#9b59b6,stroke:#7d4796,color:white
    style AnalyticsCollector fill:#f39c12,stroke:#d68910,color:white
    style AnalyticsReporter fill:#f39c12,stroke:#d68910,color:white

    style UserCore fill:#ffa64d,stroke:#cc7a30,color:white
    style ProductCore fill:#d94dbb,stroke:#a3378a,color:white
    style OrderCore fill:#4dbbbb,stroke:#368787,color:white
    style PaymentCore fill:#ff6b6b,stroke:#cc5555,color:white
    style NotificationCore fill:#9b59b6,stroke:#7d4796,color:white
    style AnalyticsCore fill:#f39c12,stroke:#d68910,color:white
    style ProductSearch fill:#d94dbb,stroke:#a3378a,color:white
    style PaymentGateway fill:#ff6b6b,stroke:#cc5555,color:white

    style SharedTypes fill:#4dbb5f,stroke:#36873f,color:white
    style SharedDb fill:#4dbb5f,stroke:#36873f,color:white
    style SharedConfig fill:#4dbb5f,stroke:#36873f,color:white
    style SharedEvents fill:#4dbb5f,stroke:#36873f,color:white
```

## 📚 SUBSYSTEM CRATE TEMPLATES

### Shared Types Crate (Domain Primitives)

```toml
# shared/shared-types/Cargo.toml
[package]
name = "shared-types"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
thiserror = { workspace = true }
serde = { workspace = true }
uuid = { workspace = true }
chrono = { workspace = true }
derive_more = { workspace = true }
typed-builder = { workspace = true }
```

```rust
// shared/shared-types/src/lib.rs
//! Shared domain primitives and types used across subsystems

pub mod ids;
pub mod money;
pub mod address;
pub mod time;
pub mod pagination;
pub mod events;

// Re-export commonly used items
pub use ids::*;
pub use money::*;
pub use address::*;
pub use time::*;
pub use pagination::*;
pub use events::*;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

```rust
// shared/shared-types/src/ids.rs
use derive_more::{Constructor, Display, From};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User identifier
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash,
    Serialize, Deserialize, Display, From, Constructor
)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

/// Product identifier
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash,
    Serialize, Deserialize, Display, From, Constructor
)]
pub struct ProductId(pub Uuid);

impl ProductId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ProductId {
    fn default() -> Self {
        Self::new()
    }
}

/// Order identifier
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash,
    Serialize, Deserialize, Display, From, Constructor
)]
pub struct OrderId(pub Uuid);

impl OrderId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for OrderId {
    fn default() -> Self {
        Self::new()
    }
}

/// Payment identifier
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash,
    Serialize, Deserialize, Display, From, Constructor
)]
pub struct PaymentId(pub Uuid);

impl PaymentId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PaymentId {
    fn default() -> Self {
        Self::new()
    }
}
```

```rust
// shared/shared-types/src/money.rs
use derive_more::{Add, Constructor, Display, From, Sub};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Currency code (ISO 4217)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Currency {
    #[serde(rename = "USD")]
    Usd,
    #[serde(rename = "EUR")]
    Eur,
    #[serde(rename = "GBP")]
    Gbp,
    #[serde(rename = "CNY")]
    Cny,
}

impl Currency {
    pub fn code(&self) -> &'static str {
        match self {
            Currency::Usd => "USD",
            Currency::Eur => "EUR",
            Currency::Gbp => "GBP",
            Currency::Cny => "CNY",
        }
    }

    pub fn decimal_places(&self) -> u8 {
        match self {
            Currency::Usd | Currency::Eur | Currency::Gbp | Currency::Cny => 2,
        }
    }
}

/// Money amount with currency
#[derive(
    Debug, Clone, Copy, PartialEq, Eq,
    Serialize, Deserialize, Constructor, Display, From
)]
#[display(fmt = "{} {}", amount, currency.code())]
pub struct Money {
    /// Amount in smallest currency unit (cents for USD)
    pub amount: i64,
    pub currency: Currency,
}

impl Money {
    pub fn new(amount: i64, currency: Currency) -> Self {
        Self { amount, currency }
    }

    pub fn zero(currency: Currency) -> Self {
        Self { amount: 0, currency }
    }

    pub fn from_major_units(major: i64, currency: Currency) -> Self {
        let multiplier = 10_i64.pow(currency.decimal_places() as u32);
        Self {
            amount: major * multiplier,
            currency
        }
    }

    pub fn to_major_units(&self) -> f64 {
        let divisor = 10_f64.powi(self.currency.decimal_places() as i32);
        self.amount as f64 / divisor
    }

    pub fn is_positive(&self) -> bool {
        self.amount > 0
    }

    pub fn is_negative(&self) -> bool {
        self.amount < 0
    }

    pub fn is_zero(&self) -> bool {
        self.amount == 0
    }
}

impl PartialOrd for Money {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.currency == other.currency {
            Some(self.amount.cmp(&other.amount))
        } else {
            None
        }
    }
}

impl Add for Money {
    type Output = Result<Money, MoneyError>;

    fn add(self, other: Self) -> Self::Output {
        if self.currency != other.currency {
            return Err(MoneyError::CurrencyMismatch {
                left: self.currency,
                right: other.currency,
            });
        }

        Ok(Money {
            amount: self.amount + other.amount,
            currency: self.currency,
        })
    }
}

impl Sub for Money {
    type Output = Result<Money, MoneyError>;

    fn sub(self, other: Self) -> Self::Output {
        if self.currency != other.currency {
            return Err(MoneyError::CurrencyMismatch {
                left: self.currency,
                right: other.currency,
            });
        }

        Ok(Money {
            amount: self.amount - other.amount,
            currency: self.currency,
        })
    }
}

/// Money-related errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum MoneyError {
    #[error("Currency mismatch: {left:?} vs {right:?}")]
    CurrencyMismatch { left: Currency, right: Currency },

    #[error("Invalid amount: {amount}")]
    InvalidAmount { amount: i64 },

    #[error("Arithmetic overflow")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_money_creation() {
        let usd_100 = Money::from_major_units(100, Currency::Usd);
        assert_eq!(usd_100.amount, 10000);
        assert_eq!(usd_100.to_major_units(), 100.0);
    }

    #[test]
    fn test_money_addition() {
        let a = Money::new(1000, Currency::Usd);
        let b = Money::new(2000, Currency::Usd);
        let result = (a + b).unwrap();
        assert_eq!(result.amount, 3000);
    }

    #[test]
    fn test_currency_mismatch() {
        let usd = Money::new(1000, Currency::Usd);
        let eur = Money::new(1000, Currency::Eur);
        assert!(matches!(usd + eur, Err(MoneyError::CurrencyMismatch { .. })));
    }
}
```

### Domain Core Crate (User Management)

```toml
# subsystems/user-management/user-core/Cargo.toml
[package]
name = "user-core"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
# Workspace dependencies
shared-types = { path = "../../../shared/shared-types" }
shared-db = { path = "../../../shared/shared-db" }
shared-events = { path = "../../../shared/shared-events" }

# External dependencies
thiserror = { workspace = true }
derive_more = { workspace = true }
typed-builder = { workspace = true }
serde = { workspace = true }
tokio = { workspace = true }
async-trait = { workspace = true }
chrono = { workspace = true }
uuid = { workspace = true }

# Domain-specific dependencies
argon2 = "0.5"
validator = { version = "0.18", features = ["derive"] }
regex = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
tokio-test = "0.4"
```

```rust
// subsystems/user-management/user-core/src/lib.rs
//! User management domain logic

pub mod entities;
pub mod services;
pub mod repositories;
pub mod errors;
pub mod events;

pub use entities::*;
pub use services::*;
pub use repositories::*;
pub use errors::*;
pub use events::*;

/// User management result type
pub type Result<T> = std::result::Result<T, UserError>;
```

```rust
// subsystems/user-management/user-core/src/entities/user.rs
use shared_types::{UserId, Timestamp};
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;
use validator::Validate;

/// User entity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TypedBuilder)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: UserId,

    #[validate(email)]
    #[builder(setter(into))]
    pub email: String,

    #[serde(skip_serializing)]
    #[builder(setter(into))]
    pub password_hash: String,

    #[builder(setter(into))]
    pub display_name: String,

    pub email_verified: bool,
    pub is_active: bool,

    pub created_at: Timestamp,
    pub updated_at: Timestamp,

    #[builder(default)]
    pub last_login_at: Option<Timestamp>,
}

impl User {
    pub fn new(email: impl Into<String>, password_hash: impl Into<String>, display_name: impl Into<String>) -> Self {
        let now = Timestamp::now();

        Self::builder()
            .id(UserId::new())
            .email(email)
            .password_hash(password_hash)
            .display_name(display_name)
            .email_verified(false)
            .is_active(true)
            .created_at(now)
            .updated_at(now)
            .build()
    }

    pub fn verify_email(&mut self) {
        self.email_verified = true;
        self.updated_at = Timestamp::now();
    }

    pub fn deactivate(&mut self) {
        self.is_active = false;
        self.updated_at = Timestamp::now();
    }

    pub fn record_login(&mut self) {
        self.last_login_at = Some(Timestamp::now());
        self.updated_at = Timestamp::now();
    }

    pub fn update_profile(&mut self, display_name: impl Into<String>) {
        self.display_name = display_name.into();
        self.updated_at = Timestamp::now();
    }
}

/// User profile for public display
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    pub id: UserId,
    pub email: String,
    pub display_name: String,
    pub email_verified: bool,
    pub created_at: Timestamp,
    pub last_login_at: Option<Timestamp>,
}

impl From<User> for UserProfile {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            email_verified: user.email_verified,
            created_at: user.created_at,
            last_login_at: user.last_login_at,
        }
    }
}

/// User registration data
#[derive(Debug, Clone, Serialize, Deserialize, Validate, TypedBuilder)]
#[serde(rename_all = "camelCase")]
pub struct UserRegistration {
    #[validate(email)]
    #[builder(setter(into))]
    pub email: String,

    #[validate(length(min = 8))]
    #[builder(setter(into))]
    pub password: String,

    #[validate(length(min = 1, max = 100))]
    #[builder(setter(into))]
    pub display_name: String,
}

/// User login credentials
#[derive(Debug, Clone, Serialize, Deserialize, Validate, TypedBuilder)]
#[serde(rename_all = "camelCase")]
pub struct UserCredentials {
    #[validate(email)]
    #[builder(setter(into))]
    pub email: String,

    #[builder(setter(into))]
    pub password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new(
            "test@example.com",
            "hashed_password",
            "Test User"
        );

        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.display_name, "Test User");
        assert!(!user.email_verified);
        assert!(user.is_active);
    }

    #[test]
    fn test_email_verification() {
        let mut user = User::new(
            "test@example.com",
            "hashed_password",
            "Test User"
        );

        user.verify_email();
        assert!(user.email_verified);
    }

    #[test]
    fn test_user_profile_conversion() {
        let user = User::new(
            "test@example.com",
            "hashed_password",
            "Test User"
        );

        let profile: UserProfile = user.into();
        assert_eq!(profile.email, "test@example.com");
        assert_eq!(profile.display_name, "Test User");
    }
}
```

## 🔄 SUBSYSTEM INTEGRATION WORKFLOW

```mermaid
sequenceDiagram
    participant Client as Client
    participant Gateway as API Gateway
    participant UserAPI as User API
    participant OrderAPI as Order API
    participant PaymentAPI as Payment API
    participant EventBus as Event Bus
    participant NotificationSvc as Notification Service

    Client->>Gateway: POST /api/orders
    Gateway->>UserAPI: Validate user token
    UserAPI->>Gateway: User authenticated
    Gateway->>OrderAPI: Create order request

    OrderAPI->>OrderAPI: Validate order data
    OrderAPI->>PaymentAPI: Process payment
    PaymentAPI->>PaymentAPI: Handle payment
    PaymentAPI->>EventBus: Publish PaymentProcessed
    PaymentAPI->>OrderAPI: Payment result

    OrderAPI->>OrderAPI: Update order status
    OrderAPI->>EventBus: Publish OrderPlaced
    OrderAPI->>Gateway: Order created
    Gateway->>Client: Order response

    EventBus->>NotificationSvc: OrderPlaced event
    NotificationSvc->>NotificationSvc: Send confirmation email
```

## 📝 SUBSYSTEM DEVELOPMENT SCRIPTS

### Build Script (scripts/build-subsystem.sh)

```bash
#!/bin/bash
set -e

SUBSYSTEM=$1

if [ -z "$SUBSYSTEM" ]; then
    echo "Usage: $0 <subsystem-name>"
    echo "Available subsystems: user-management, product-catalog, order-management, payment, notification, analytics"
    exit 1
fi

echo "Building $SUBSYSTEM subsystem..."

# Build core crate
if [ -d "subsystems/$SUBSYSTEM" ]; then
    cd "subsystems/$SUBSYSTEM"

    # Find and build all crates in subsystem
    for crate_dir in */; do
        if [ -f "$crate_dir/Cargo.toml" ]; then
            echo "Building $crate_dir..."
            cd "$crate_dir"
            cargo build --all-features
            cargo test --all-features
            cargo clippy -- -D warnings
            cd ..
        fi
    done

    cd ../..
else
    echo "Subsystem '$SUBSYSTEM' not found"
    exit 1
fi

echo "$SUBSYSTEM subsystem build completed successfully!"
```

### Integration Test Script (scripts/test-integration.sh)

```bash
#!/bin/bash
set -e

echo "Running integration tests..."

# Start test dependencies
docker-compose -f docker-compose.test.yml up -d postgres redis

# Wait for services to be ready
echo "Waiting for test services..."
sleep 10

# Run database migrations
cargo run --bin migration-tool -- --env test migrate up

# Run integration tests
cargo test --test integration_tests --all-features

# Run end-to-end tests
cargo test --test e2e_tests --all-features

# Cleanup
docker-compose -f docker-compose.test.yml down

echo "Integration tests completed successfully!"
```

## 📋 SUBSYSTEM DESIGN CHECKLIST

```markdown
## Subsystem Architecture Verification

### Subsystem Boundaries
- [ ] Each subsystem has clear business domain responsibility
- [ ] Subsystems communicate only through well-defined interfaces
- [ ] Shared infrastructure is properly abstracted
- [ ] Domain events are used for cross-subsystem communication
- [ ] No direct database access between subsystems

### Code Organization
- [ ] Core business logic is separated from infrastructure
- [ ] API layers are thin and focused on HTTP concerns
- [ ] Worker/processor crates handle background operations
- [ ] Shared types define domain primitives consistently
- [ ] Error types are subsystem-specific but composable

### Dependency Management
- [ ] Subsystem dependencies follow layer architecture
- [ ] No circular dependencies between subsystems
- [ ] Shared crates are only for cross-cutting concerns
- [ ] External dependencies are centralized in workspace
- [ ] Version consistency maintained across subsystems

### Testing Strategy
- [ ] Unit tests cover domain logic in core crates
- [ ] Integration tests verify subsystem boundaries
- [ ] End-to-end tests cover business workflows
- [ ] Performance tests validate scalability
- [ ] Contract tests ensure API compatibility

### Documentation
- [ ] Subsystem README explains business purpose
- [ ] API documentation is auto-generated and current
- [ ] Architecture decisions are documented
- [ ] Deployment guides are subsystem-specific
- [ ] Monitoring and alerting guidelines exist

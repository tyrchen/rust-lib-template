---
description:
globs:
alwaysApply: false
---
# 🎨 RUST API DESIGN BEST PRACTICES

> **TL;DR:** Comprehensive API design guidelines for creating ergonomic, maintainable, and idiomatic Rust libraries and services.

## 🔍 API DESIGN STRATEGY

```mermaid
graph TD
    Start["API Design"] --> Purpose{"API<br>Purpose?"}

    Purpose -->|Library| LibAPI["Library API"]
    Purpose -->|Service| ServiceAPI["Service API"]
    Purpose -->|CLI| CLIAPI["CLI API"]

    LibAPI --> Ergonomics["Ergonomic Design"]
    ServiceAPI --> RESTDesign["REST/gRPC Design"]
    CLIAPI --> CLIDesign["Command Interface"]

    Ergonomics --> FlexibleInputs["Flexible Input Types"]
    Ergonomics --> BuilderPattern["Builder Pattern"]
    Ergonomics --> ErrorDesign["Error Design"]

    RESTDesign --> OpenAPI["OpenAPI Documentation"]
    RESTDesign --> Validation["Input Validation"]
    RESTDesign --> Authentication["Authentication"]

    CLIDesign --> Subcommands["Subcommand Structure"]
    CLIDesign --> Configuration["Configuration Management"]
    CLIDesign --> HelpSystem["Help System"]

    FlexibleInputs --> TraitDesign["Trait Design"]
    BuilderPattern --> TraitDesign
    ErrorDesign --> TraitDesign

    OpenAPI --> AsyncAPI["Async API Patterns"]
    Validation --> AsyncAPI
    Authentication --> AsyncAPI

    Subcommands --> Testing["Testing Strategy"]
    Configuration --> Testing
    HelpSystem --> Testing

    TraitDesign --> Documentation["Documentation"]
    AsyncAPI --> Documentation
    Testing --> Documentation

    Documentation --> APIComplete["API Complete"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style Ergonomics fill:#4dbb5f,stroke:#36873f,color:white
    style RESTDesign fill:#ffa64d,stroke:#cc7a30,color:white
    style CLIDesign fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 API DESIGN PRINCIPLES

### Ergonomic Function Signatures
```rust
use std::path::Path;

// ✅ Accept flexible input types
pub fn read_config<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    let path = path.as_ref();
    // Implementation
}

// ✅ Use Into for string-like parameters
pub fn create_user<S: Into<String>>(name: S, email: S) -> Result<User, UserError> {
    let name = name.into();
    let email = email.into();
    // Implementation
}

// ✅ Prefer borrowing over ownership when possible
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    // Implementation - doesn't need to own the string
}

// ✅ Return owned data when caller needs ownership
pub fn generate_token() -> String {
    // Implementation returns owned String
}

// ❌ Avoid overly generic signatures without clear benefit
// pub fn process<T, U, F>(input: T, func: F) -> U where F: Fn(T) -> U
```

### Builder Pattern Implementation
```rust
use typed_builder::TypedBuilder;

// ✅ Use TypedBuilder for complex configuration
#[derive(Debug, TypedBuilder)]
pub struct HttpClient {
    #[builder(setter(into))]
    base_url: String,

    #[builder(default = Duration::from_secs(30))]
    timeout: Duration,

    #[builder(default)]
    headers: HashMap<String, String>,

    #[builder(default, setter(strip_option))]
    proxy: Option<String>,

    #[builder(default = false)]
    verify_ssl: bool,
}

impl HttpClient {
    // ✅ Provide a simple constructor for common cases
    pub fn new<S: Into<String>>(base_url: S) -> Self {
        Self::builder()
            .base_url(base_url)
            .build()
    }

    // ✅ Provide convenient factory methods
    pub fn with_auth<S: Into<String>>(base_url: S, token: S) -> Self {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", token.into()));

        Self::builder()
            .base_url(base_url)
            .headers(headers)
            .build()
    }
}

// ✅ Usage examples
let client = HttpClient::new("https://api.example.com");

let authenticated_client = HttpClient::builder()
    .base_url("https://api.example.com")
    .timeout(Duration::from_secs(60))
    .verify_ssl(true)
    .build();
```

### Error Handling Design
```rust
use thiserror::Error;

// ✅ Well-structured error hierarchy
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Network error: {source}")]
    Network {
        #[from]
        source: reqwest::Error,
    },

    #[error("Invalid request: {message}")]
    InvalidRequest { message: String },

    #[error("Authentication failed")]
    Authentication,

    #[error("Resource not found: {resource_type} with id {id}")]
    NotFound {
        resource_type: String,
        id: String,
    },

    #[error("Rate limit exceeded: retry after {retry_after} seconds")]
    RateLimit { retry_after: u64 },

    #[error("Server error: {status_code}")]
    Server { status_code: u16 },
}

impl ApiError {
    // ✅ Provide utility methods for error classification
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ApiError::Network { .. } | ApiError::RateLimit { .. } | ApiError::Server { status_code } if *status_code >= 500
        )
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            ApiError::RateLimit { retry_after } => Some(Duration::from_secs(*retry_after)),
            _ => None,
        }
    }
}

// ✅ Domain-specific result type
pub type ApiResult<T> = Result<T, ApiError>;
```

## 🔄 TRAIT DESIGN PATTERNS

### Cohesive Trait Design
```rust
// ✅ Single responsibility traits
pub trait Serializable {
    fn serialize(&self) -> Result<Vec<u8>, SerializationError>;
    fn deserialize(data: &[u8]) -> Result<Self, SerializationError>
    where
        Self: Sized;
}

pub trait Cacheable {
    type Key;
    fn cache_key(&self) -> Self::Key;
    fn cache_ttl(&self) -> Option<Duration>;
}

// ✅ Composable traits
pub trait Repository<T> {
    type Error;
    type Id;

    async fn find_by_id(&self, id: Self::Id) -> Result<Option<T>, Self::Error>;
    async fn save(&self, entity: &T) -> Result<T, Self::Error>;
    async fn delete(&self, id: Self::Id) -> Result<bool, Self::Error>;
}

pub trait Queryable<T>: Repository<T> {
    type Query;
    type Page;

    async fn find_by_query(&self, query: Self::Query) -> Result<Vec<T>, Self::Error>;
    async fn find_paginated(&self, query: Self::Query, page: Self::Page) -> Result<(Vec<T>, bool), Self::Error>;
}

// ✅ Default implementations for common patterns
pub trait Timestamped {
    fn created_at(&self) -> DateTime<Utc>;
    fn updated_at(&self) -> DateTime<Utc>;

    // Default implementation for age calculation
    fn age(&self) -> Duration {
        Utc::now().signed_duration_since(self.created_at()).to_std().unwrap_or_default()
    }
}
```

### Extension Traits
```rust
// ✅ Extension traits for external types
pub trait StringExtensions {
    fn is_valid_email(&self) -> bool;
    fn to_snake_case(&self) -> String;
    fn truncate_with_ellipsis(&self, max_len: usize) -> String;
}

impl StringExtensions for str {
    fn is_valid_email(&self) -> bool {
        // Email validation logic
        self.contains('@') && self.contains('.')
    }

    fn to_snake_case(&self) -> String {
        // Snake case conversion
        self.chars()
            .map(|c| if c.is_uppercase() { format!("_{}", c.to_lowercase()) } else { c.to_string() })
            .collect::<String>()
            .trim_start_matches('_')
            .to_string()
    }

    fn truncate_with_ellipsis(&self, max_len: usize) -> String {
        if self.len() <= max_len {
            self.to_string()
        } else {
            format!("{}...", &self[..max_len.saturating_sub(3)])
        }
    }
}

// ✅ Extension traits for Result types
pub trait ResultExtensions<T, E> {
    fn log_error(self) -> Self;
    fn with_context<F>(self, f: F) -> Result<T, ContextError<E>>
    where
        F: FnOnce() -> String;
}

impl<T, E: std::fmt::Debug> ResultExtensions<T, E> for Result<T, E> {
    fn log_error(self) -> Self {
        if let Err(ref e) = self {
            tracing::error!("Operation failed: {:?}", e);
        }
        self
    }

    fn with_context<F>(self, f: F) -> Result<T, ContextError<E>>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| ContextError {
            context: f(),
            source: e,
        })
    }
}
```

## 📦 MODULE ORGANIZATION

### Public API Structure
```rust
// lib.rs - Main library entry point
//! # MyLibrary
//!
//! A comprehensive library for handling X, Y, and Z.
//!
//! ## Quick Start
//!
//! ```rust
//! use my_library::Client;
//!
//! let client = Client::new("api-key");
//! let result = client.fetch_data().await?;
//! ```
//!
//! ## Features
//!
//! - Feature A: Enable with `features = ["feature-a"]`
//! - Feature B: Enable with `features = ["feature-b"]`

// Re-export main public API
pub use client::Client;
pub use config::Config;
pub use error::{Error, Result};

// Re-export important types
pub use types::{User, Product, Order};

// Module declarations
mod client;
mod config;
mod error;
mod types;

// Internal modules (not re-exported)
mod internal {
    pub mod auth;
    pub mod http;
    pub mod serialization;
}

// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{Client, Config, Error, Result};
    pub use crate::types::*;
}

// Feature-gated modules
#[cfg(feature = "async")]
pub mod async_client;

#[cfg(feature = "blocking")]
pub mod blocking_client;
```

### Documentation Standards
```rust
/// A client for interacting with the Example API.
///
/// The `Client` provides methods for authentication, data retrieval,
/// and resource management. It handles rate limiting, retries, and
/// error handling automatically.
///
/// # Examples
///
/// Basic usage:
///
/// ```rust
/// use my_library::Client;
///
/// # tokio_test::block_on(async {
/// let client = Client::new("your-api-key");
/// let users = client.list_users().await?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # });
/// ```
///
/// With custom configuration:
///
/// ```rust
/// use my_library::{Client, Config};
/// use std::time::Duration;
///
/// let config = Config::builder()
///     .timeout(Duration::from_secs(30))
///     .retry_attempts(3)
///     .build();
///
/// let client = Client::with_config("your-api-key", config);
/// ```
pub struct Client {
    api_key: String,
    config: Config,
    http_client: reqwest::Client,
}

impl Client {
    /// Creates a new client with the given API key.
    ///
    /// Uses default configuration with reasonable timeouts and retry settings.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your API key for authentication
    ///
    /// # Examples
    ///
    /// ```rust
    /// use my_library::Client;
    ///
    /// let client = Client::new("sk-1234567890abcdef");
    /// ```
    pub fn new<S: Into<String>>(api_key: S) -> Self {
        Self::with_config(api_key, Config::default())
    }

    /// Creates a new client with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your API key for authentication
    /// * `config` - Custom configuration settings
    ///
    /// # Examples
    ///
    /// ```rust
    /// use my_library::{Client, Config};
    /// use std::time::Duration;
    ///
    /// let config = Config::builder()
    ///     .timeout(Duration::from_secs(60))
    ///     .build();
    ///
    /// let client = Client::with_config("api-key", config);
    /// ```
    pub fn with_config<S: Into<String>>(api_key: S, config: Config) -> Self {
        // Implementation
    }

    /// Retrieves a list of users.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of `User` objects on success,
    /// or an `Error` on failure.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * The API key is invalid (`Error::Authentication`)
    /// * The request times out (`Error::Network`)
    /// * The server returns an error (`Error::Server`)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use my_library::{Client, Error};
    /// # tokio_test::block_on(async {
    /// let client = Client::new("api-key");
    ///
    /// match client.list_users().await {
    ///     Ok(users) => println!("Found {} users", users.len()),
    ///     Err(Error::Authentication) => eprintln!("Invalid API key"),
    ///     Err(e) => eprintln!("Request failed: {}", e),
    /// }
    /// # });
    /// ```
    pub async fn list_users(&self) -> Result<Vec<User>, Error> {
        // Implementation
    }
}
```

## 🔧 CONFIGURATION PATTERNS

### Layered Configuration
```rust
use serde::{Deserialize, Serialize};
use std::path::Path;

// ✅ Configuration with multiple sources
#[derive(Debug, Clone, Serialize, Deserialize, TypedBuilder)]
pub struct Config {
    // Server settings
    #[builder(default = "127.0.0.1".to_string(), setter(into))]
    pub host: String,

    #[builder(default = 8080)]
    pub port: u16,

    // API settings
    #[builder(default = Duration::from_secs(30))]
    pub timeout: Duration,

    #[builder(default = 3)]
    pub retry_attempts: u32,

    // Feature flags
    #[builder(default = true)]
    pub enable_metrics: bool,

    #[builder(default = false)]
    pub debug_mode: bool,
}

impl Config {
    /// Load configuration from multiple sources with precedence:
    /// 1. Environment variables (highest priority)
    /// 2. Configuration file
    /// 3. Defaults (lowest priority)
    pub fn load() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        // Load from file if it exists
        if let Ok(file_config) = Self::from_file("config.toml") {
            config = config.merge(file_config);
        }

        // Override with environment variables
        config = config.merge(Self::from_env()?);

        Ok(config)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(ConfigError::FileRead)?;

        toml::from_str(&content)
            .map_err(ConfigError::ParseError)
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let mut builder = Self::builder();

        if let Ok(host) = std::env::var("HOST") {
            builder = builder.host(host);
        }

        if let Ok(port) = std::env::var("PORT") {
            let port = port.parse()
                .map_err(|_| ConfigError::InvalidPort)?;
            builder = builder.port(port);
        }

        if let Ok(timeout) = std::env::var("TIMEOUT_SECONDS") {
            let seconds = timeout.parse()
                .map_err(|_| ConfigError::InvalidTimeout)?;
            builder = builder.timeout(Duration::from_secs(seconds));
        }

        Ok(builder.build())
    }

    fn merge(self, other: Self) -> Self {
        // Merge logic - other takes precedence
        Self {
            host: if other.host != "127.0.0.1" { other.host } else { self.host },
            port: if other.port != 8080 { other.port } else { self.port },
            timeout: if other.timeout != Duration::from_secs(30) { other.timeout } else { self.timeout },
            retry_attempts: if other.retry_attempts != 3 { other.retry_attempts } else { self.retry_attempts },
            enable_metrics: other.enable_metrics, // Boolean fields always take the other value
            debug_mode: other.debug_mode,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::builder().build()
    }
}
```

## 🎭 ASYNC API PATTERNS

### Async Iterator and Stream Design
```rust
use futures::Stream;
use std::pin::Pin;

// ✅ Async iterator for paginated results
pub struct PaginatedStream<T> {
    client: Arc<Client>,
    query: Query,
    current_page: Option<String>,
    buffer: VecDeque<T>,
    exhausted: bool,
}

impl<T> PaginatedStream<T> {
    pub fn new(client: Arc<Client>, query: Query) -> Self {
        Self {
            client,
            query,
            current_page: None,
            buffer: VecDeque::new(),
            exhausted: false,
        }
    }
}

impl<T: Unpin> Stream for PaginatedStream<T>
where
    T: for<'de> Deserialize<'de> + Send + 'static,
{
    type Item = Result<T, ApiError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if let Some(item) = self.buffer.pop_front() {
            return Poll::Ready(Some(Ok(item)));
        }

        if self.exhausted {
            return Poll::Ready(None);
        }

        // Fetch next page
        let client = self.client.clone();
        let query = self.query.clone();
        let page = self.current_page.clone();

        let future = async move {
            client.fetch_page(query, page).await
        };

        // Poll the future and handle the result
        // Implementation depends on your async runtime
        todo!("Implement polling logic")
    }
}

// ✅ Cancellation-aware async operations
pub struct CancellableOperation<T> {
    inner: Pin<Box<dyn Future<Output = Result<T, ApiError>> + Send>>,
    cancel_token: CancelToken,
}

impl<T> CancellableOperation<T> {
    pub fn new<F>(future: F, cancel_token: CancelToken) -> Self
    where
        F: Future<Output = Result<T, ApiError>> + Send + 'static,
    {
        Self {
            inner: Box::pin(future),
            cancel_token,
        }
    }
}

impl<T> Future for CancellableOperation<T> {
    type Output = Result<T, ApiError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cancel_token.is_cancelled() {
            return Poll::Ready(Err(ApiError::Cancelled));
        }

        self.inner.as_mut().poll(cx)
    }
}
```

## 🔍 TESTING API DESIGN

### Testable API Structure
```rust
// ✅ Dependency injection for testability
pub trait HttpClientTrait: Send + Sync {
    async fn get(&self, url: &str) -> Result<Response, HttpError>;
    async fn post(&self, url: &str, body: Vec<u8>) -> Result<Response, HttpError>;
}

pub struct Client<H: HttpClientTrait> {
    http_client: H,
    config: Config,
}

impl<H: HttpClientTrait> Client<H> {
    pub fn new(http_client: H, config: Config) -> Self {
        Self { http_client, config }
    }

    pub async fn fetch_user(&self, id: &str) -> Result<User, ApiError> {
        let url = format!("{}/users/{}", self.config.base_url, id);
        let response = self.http_client.get(&url).await?;
        // Parse response
        todo!()
    }
}

// ✅ Production implementation
impl HttpClientTrait for reqwest::Client {
    async fn get(&self, url: &str) -> Result<Response, HttpError> {
        // Implementation
    }

    async fn post(&self, url: &str, body: Vec<u8>) -> Result<Response, HttpError> {
        // Implementation
    }
}

// ✅ Mock implementation for testing
#[cfg(test)]
pub struct MockHttpClient {
    responses: HashMap<String, Result<Response, HttpError>>,
}

#[cfg(test)]
impl MockHttpClient {
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
        }
    }

    pub fn expect_get(&mut self, url: &str, response: Result<Response, HttpError>) {
        self.responses.insert(format!("GET {}", url), response);
    }
}

#[cfg(test)]
impl HttpClientTrait for MockHttpClient {
    async fn get(&self, url: &str) -> Result<Response, HttpError> {
        self.responses
            .get(&format!("GET {}", url))
            .cloned()
            .unwrap_or(Err(HttpError::NotFound))
    }

    async fn post(&self, url: &str, _body: Vec<u8>) -> Result<Response, HttpError> {
        self.responses
            .get(&format!("POST {}", url))
            .cloned()
            .unwrap_or(Err(HttpError::NotFound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_user_success() {
        let mut mock_client = MockHttpClient::new();
        mock_client.expect_get(
            "https://api.example.com/users/123",
            Ok(Response {
                status: 200,
                body: r#"{"id": "123", "name": "John"}"#.to_string(),
            }),
        );

        let client = Client::new(mock_client, Config::default());
        let user = client.fetch_user("123").await.unwrap();

        assert_eq!(user.id, "123");
        assert_eq!(user.name, "John");
    }
}
```

## ✅ API DESIGN CHECKLIST

```markdown
### API Design Implementation Verification
- [ ] Function signatures accept flexible input types (AsRef, Into)
- [ ] Error types are well-structured with proper context
- [ ] Builder pattern used for complex configuration
- [ ] Traits have single responsibility and clear contracts
- [ ] Public API is well-documented with examples
- [ ] Configuration supports multiple sources with precedence
- [ ] Async APIs handle cancellation and backpressure
- [ ] Dependencies are injected for testability
- [ ] Extension traits enhance existing types ergonomically
- [ ] Module organization follows convention
- [ ] Feature gates are used appropriately
- [ ] Error handling provides actionable information
- [ ] API follows Rust naming conventions
- [ ] Generic parameters have appropriate bounds
- [ ] Public API surface is minimal but complete
```

This API design guide ensures consistent, ergonomic, and maintainable interfaces across Rust projects.

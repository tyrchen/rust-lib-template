---
description:
globs:
alwaysApply: false
---
# 🌐 HTTP CLIENT BEST PRACTICES

> **TL;DR:** Modern HTTP client patterns using reqwest with proper error handling, timeouts, and security configurations.

## 🔍 HTTP CLIENT ARCHITECTURE STRATEGY

```mermaid
graph TD
    Start["HTTP Client Requirements"] --> ClientType{"Client<br>Usage Pattern?"}

    ClientType -->|Simple Requests| SimpleClient["Simple Request Pattern"]
    ClientType -->|Complex Integration| AdvancedClient["Advanced Client Pattern"]
    ClientType -->|Service Integration| ServiceClient["Service Client Pattern"]

    SimpleClient --> BasicConfig["Basic Configuration"]
    AdvancedClient --> BuilderPattern["Builder Pattern"]
    ServiceClient --> TypedClient["Typed Client"]

    BasicConfig --> ErrorHandling["Error Handling"]
    BuilderPattern --> ErrorHandling
    TypedClient --> ErrorHandling

    ErrorHandling --> RetryLogic["Retry Logic"]
    RetryLogic --> Authentication["Authentication"]
    Authentication --> Monitoring["Request Monitoring"]

    Monitoring --> Testing["Client Testing"]
    Testing --> Production["Production HTTP Client"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style SimpleClient fill:#4dbb5f,stroke:#36873f,color:white
    style AdvancedClient fill:#ffa64d,stroke:#cc7a30,color:white
    style ServiceClient fill:#d94dbb,stroke:#a3378a,color:white
```

## 🔧 REQWEST CONFIGURATION

### Standard Dependencies
```toml
# Cargo.toml - HTTP client configuration
[dependencies]
reqwest = { version = "0.12", default-features = false, features = [
    "charset",
    "rustls-tls-webpki-roots",
    "http2",
    "json",
    "cookies",
    "gzip",
    "brotli",
    "zstd",
    "deflate"
] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.45", features = ["macros", "rt-multi-thread"] }
anyhow = "1.0"
thiserror = "2.0"
url = "2.5"
```

## 🏗️ CLIENT BUILDER PATTERN

### Configurable HTTP Client
```rust
use reqwest::{Client, ClientBuilder, Response};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

pub struct HttpClient {
    client: Client,
    base_url: Url,
    default_timeout: Duration,
}

impl HttpClient {
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

    pub async fn get<T>(&self, path: &str) -> Result<T, HttpError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = self.base_url.join(path)?;

        let response = self
            .client
            .get(url)
            .timeout(self.default_timeout)
            .send()
            .await?;

        self.handle_response(response).await
    }

    pub async fn post<T, B>(&self, path: &str, body: &B) -> Result<T, HttpError>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize,
    {
        let url = self.base_url.join(path)?;

        let response = self
            .client
            .post(url)
            .json(body)
            .timeout(self.default_timeout)
            .send()
            .await?;

        self.handle_response(response).await
    }

    async fn handle_response<T>(&self, response: Response) -> Result<T, HttpError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();

        if status.is_success() {
            let text = response.text().await?;
            serde_json::from_str(&text).map_err(|e| HttpError::Deserialization {
                error: e.to_string(),
                body: text,
            })
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(HttpError::UnexpectedStatus {
                status: status.as_u16(),
                body,
            })
        }
    }
}

pub struct HttpClientBuilder {
    base_url: Option<String>,
    timeout: Option<Duration>,
    user_agent: Option<String>,
    headers: Vec<(String, String)>,
    accept_invalid_certs: bool,
}

impl HttpClientBuilder {
    pub fn new() -> Self {
        Self {
            base_url: None,
            timeout: Some(Duration::from_secs(30)),
            user_agent: Some("rust-http-client/1.0".to_string()),
            headers: Vec::new(),
            accept_invalid_certs: false,
        }
    }

    pub fn base_url(mut self, url: &str) -> Self {
        self.base_url = Some(url.to_string());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn build(self) -> Result<HttpClient, HttpError> {
        let base_url = self.base_url
            .ok_or_else(|| HttpError::Configuration("Base URL is required".to_string()))?;

        let mut client_builder = ClientBuilder::new()
            .danger_accept_invalid_certs(self.accept_invalid_certs);

        if let Some(timeout) = self.timeout {
            client_builder = client_builder.timeout(timeout);
        }

        if let Some(user_agent) = &self.user_agent {
            client_builder = client_builder.user_agent(user_agent);
        }

        let client = client_builder.build()?;
        let parsed_url = Url::parse(&base_url)?;

        Ok(HttpClient {
            client,
            base_url: parsed_url,
            default_timeout: self.timeout.unwrap_or(Duration::from_secs(30)),
        })
    }
}
```

## 🚨 ERROR HANDLING

### Comprehensive Error Types
```rust
#[derive(thiserror::Error, Debug)]
pub enum HttpError {
    #[error("HTTP request error: {0}")]
    Request(#[from] reqwest::Error),

    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Deserialization error: {error}, body: {body}")]
    Deserialization { error: String, body: String },

    #[error("Unexpected HTTP status {status}: {body}")]
    UnexpectedStatus { status: u16, body: String },

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Timeout occurred")]
    Timeout,

    #[error("Authentication failed")]
    Authentication,
}

impl HttpError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            HttpError::Timeout
                | HttpError::UnexpectedStatus { status: 502..=504, .. }
        )
    }
}
```

## ✅ HTTP CLIENT CHECKLIST

```markdown
### HTTP Client Implementation Verification
- [ ] Uses reqwest with rustls-tls (not native-tls)
- [ ] Compression features enabled (gzip, brotli, deflate)
- [ ] Proper timeout configuration
- [ ] User-Agent header configured
- [ ] Structured error handling with retryable errors
- [ ] Authentication patterns implemented
- [ ] Response type definitions with camelCase
- [ ] Base URL configuration pattern
- [ ] JSON serialization/deserialization
- [ ] Proper status code handling
```

This HTTP client standard ensures robust, secure, and maintainable HTTP communication in Rust applications.

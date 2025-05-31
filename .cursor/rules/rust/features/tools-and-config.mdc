---
description:
globs:
alwaysApply: false
---
# 🛠️ TOOLS AND CONFIGURATION BEST PRACTICES

> **TL;DR:** Essential tools and configuration patterns for modern Rust applications, focusing on logging, configuration management, and templating.

## 🔍 TOOLS & CONFIGURATION STRATEGY

```mermaid
graph TD
    Start["Application Setup"] --> ConfigType{"Configuration<br>Complexity?"}

    ConfigType -->|Simple| EnvVars["Environment Variables"]
    ConfigType -->|Complex| YAMLConfig["YAML Configuration"]

    EnvVars --> Logging["Logging Setup"]
    YAMLConfig --> ConfigValidation["Configuration Validation"]
    ConfigValidation --> Logging

    Logging --> StructuredLogging["Structured Logging"]
    StructuredLogging --> LogRotation["Log Rotation"]

    LogRotation --> Templating{"Template<br>Engine Needed?"}

    Templating -->|Yes| MiniJinja["MiniJinja Templates"]
    Templating -->|No| DataProcessing["Data Processing"]

    MiniJinja --> DataProcessing
    DataProcessing --> JSONPath["JSON Path Extraction"]

    JSONPath --> Monitoring["Application Monitoring"]
    Monitoring --> Production["Production Tools"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style YAMLConfig fill:#4dbb5f,stroke:#36873f,color:white
    style StructuredLogging fill:#ffa64d,stroke:#cc7a30,color:white
    style MiniJinja fill:#d94dbb,stroke:#a3378a,color:white
```

## 📊 LOGGING AND OBSERVABILITY

### Tracing Ecosystem (Not env_logger)
- **Always use `tracing`** - modern structured logging
- **Combine with `tracing-subscriber`** for output formatting
- **File rotation with `tracing-appender`** for production
- **Structured logging** with spans and events

```toml
# Cargo.toml - Tracing configuration
[dependencies]
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
chrono = { version = "0.4", features = ["serde"] }
```

### Structured Logging Setup
```rust
use tracing::{info, error, warn, debug, span, Level};
use tracing_subscriber::{
    fmt::{self, time::ChronoUtc},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
    Registry,
};
use tracing_appender::{non_blocking, rolling};

pub fn init_logging(config: &LogConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Create file appender with rotation
    let file_appender = rolling::daily(&config.log_dir, "app.log");
    let (file_writer, _guard) = non_blocking(file_appender);

    // Console formatting
    let console_layer = fmt::layer()
        .with_target(true)
        .with_timer(ChronoUtc::rfc_3339())
        .with_level(true)
        .with_thread_ids(true)
        .with_thread_names(true);

    // File formatting (JSON for structured logs)
    let file_layer = fmt::layer()
        .json()
        .with_timer(ChronoUtc::rfc_3339())
        .with_writer(file_writer);

    // Environment filter
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    Registry::default()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    Ok(())
}

// Usage in application code
#[tracing::instrument(skip(service), fields(user_id = %user_id))]
pub async fn process_user_registration(
    user_id: &str,
    service: &UserService,
) -> Result<User, ServiceError> {
    let span = span!(Level::INFO, "user_registration", user_id = %user_id);
    let _enter = span.enter();

    info!("Starting user registration process");

    let user = service.create_user(user_id).await.map_err(|e| {
        error!("Failed to create user: {}", e);
        e
    })?;

    info!(
        user_id = %user.id,
        email = %user.email,
        "User registration completed successfully"
    );

    Ok(user)
}

// Contextual logging with structured fields
pub async fn handle_payment_processing(
    order_id: &str,
    amount: f64,
    payment_method: &str,
) -> Result<PaymentResult, PaymentError> {
    let span = span!(
        Level::INFO,
        "payment_processing",
        order_id = %order_id,
        amount = %amount,
        payment_method = %payment_method
    );
    let _enter = span.enter();

    info!("Processing payment");

    match process_payment(order_id, amount, payment_method).await {
        Ok(result) => {
            info!(
                transaction_id = %result.transaction_id,
                status = %result.status,
                "Payment processed successfully"
            );
            Ok(result)
        }
        Err(e) => {
            error!(
                error = %e,
                "Payment processing failed"
            );
            Err(e)
        }
    }
}
```

## ⚙️ CONFIGURATION MANAGEMENT

### YAML Over TOML for Complex Configuration
- **Use YAML** for application configuration (not TOML)
- **Environment-specific configs** (dev, staging, prod)
- **Sensitive data via environment variables**
- **Configuration validation** using serde and custom validation

```yaml
# config/development.yaml
server:
  host: "127.0.0.1"
  port: 8080
  workers: 1

database:
  url: "postgresql://user:pass@localhost/app_dev"
  maxConnections: 10
  minConnections: 2
  connectTimeout: 30s
  idleTimeout: 600s

logging:
  level: "debug"
  format: "pretty"
  logDir: "./logs"

email:
  provider: "smtp"
  smtpHost: "localhost"
  smtpPort: 1025
  fromAddress: "noreply@example.com"

features:
  enableRegistration: true
  enablePasswordReset: true
  enableEmailVerification: false
  maintenanceMode: false

cache:
  redis:
    url: "redis://localhost:6379"
    maxConnections: 10
    defaultTtl: 3600

security:
  jwtSecret: "${JWT_SECRET}"  # From environment
  sessionTimeout: 3600
  rateLimitRequests: 100
  rateLimitWindow: 60
```

### Configuration Loading Pattern
```rust
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub logging: LogConfig,
    pub email: EmailConfig,
    pub features: FeatureFlags,
    pub cache: CacheConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    #[serde(with = "duration_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "duration_serde")]
    pub idle_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureFlags {
    pub enable_registration: bool,
    pub enable_password_reset: bool,
    pub enable_email_verification: bool,
    pub maintenance_mode: bool,
}

// Configuration loading with environment override
impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let env = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let config_path = format!("config/{}.yaml", env);

        let mut settings = config::Config::builder()
            .add_source(config::File::with_name(&config_path))
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;

        // Expand environment variables
        settings.try_deserialize()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.port == 0 {
            return Err(ConfigError::InvalidValue("Server port cannot be 0".to_string()));
        }

        if self.database.max_connections < self.database.min_connections {
            return Err(ConfigError::InvalidValue(
                "max_connections must be >= min_connections".to_string()
            ));
        }

        if self.security.session_timeout == 0 {
            return Err(ConfigError::InvalidValue("Session timeout must be > 0".to_string()));
        }

        Ok(())
    }
}

// Custom duration serialization for human-readable durations
mod duration_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = duration.as_secs();
        serializer.serialize_str(&format!("{}s", secs))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.ends_with("s") {
            let num: u64 = s[..s.len()-1].parse().map_err(serde::de::Error::custom)?;
            Ok(Duration::from_secs(num))
        } else {
            Err(serde::de::Error::custom("Duration must end with 's'"))
        }
    }
}
```

## 📄 TEMPLATING WITH MINIJINJA

### MiniJinja Over Handlebars
- **Use MiniJinja** for templating (not Handlebars)
- **Custom filters and functions** for application-specific logic
- **Template inheritance** for reusable layouts
- **Auto-escaping** for security

```toml
# Cargo.toml - MiniJinja configuration
[dependencies]
minijinja = { version = "2", features = [
    "json",
    "loader",
    "loop_controls",
    "speedups"
] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

### Template Engine Setup
```rust
use minijinja::{Environment, Error as TemplateError};
use std::collections::HashMap;

pub struct TemplateEngine {
    env: Environment<'static>,
}

impl TemplateEngine {
    pub fn new() -> Result<Self, TemplateError> {
        let mut env = Environment::new();

        // Load templates from directory
        env.set_loader(minijinja::path_loader("templates"));

        // Add custom filters
        env.add_filter("currency", currency_filter);
        env.add_filter("date_format", date_format_filter);
        env.add_filter("truncate", truncate_filter);

        // Add custom functions
        env.add_function("asset_url", asset_url_function);
        env.add_function("config", config_function);

        Ok(Self { env })
    }

    pub fn render_email_template(
        &self,
        template_name: &str,
        context: &EmailContext,
    ) -> Result<String, TemplateError> {
        let template = self.env.get_template(template_name)?;
        template.render(context)
    }

    pub fn render_notification(
        &self,
        template_name: &str,
        context: &NotificationContext,
    ) -> Result<String, TemplateError> {
        let template = self.env.get_template(template_name)?;
        template.render(context)
    }
}

// Custom filters
fn currency_filter(value: f64, _args: &[minijinja::Value]) -> Result<String, TemplateError> {
    Ok(format!("${:.2}", value))
}

fn date_format_filter(
    value: chrono::DateTime<chrono::Utc>,
    args: &[minijinja::Value],
) -> Result<String, TemplateError> {
    let format = args
        .get(0)
        .and_then(|v| v.as_str())
        .unwrap_or("%Y-%m-%d %H:%M:%S");
    Ok(value.format(format).to_string())
}

fn truncate_filter(
    value: String,
    args: &[minijinja::Value],
) -> Result<String, TemplateError> {
    let length = args
        .get(0)
        .and_then(|v| v.as_i64())
        .unwrap_or(100) as usize;

    if value.len() <= length {
        Ok(value)
    } else {
        Ok(format!("{}...", &value[..length]))
    }
}

// Custom functions
fn asset_url_function(args: &[minijinja::Value]) -> Result<String, TemplateError> {
    let path = args
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| TemplateError::new("asset_url requires a path argument"))?;

    Ok(format!("/assets/{}", path))
}

fn config_function(args: &[minijinja::Value]) -> Result<minijinja::Value, TemplateError> {
    let key = args
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| TemplateError::new("config requires a key argument"))?;

    // Access application configuration
    match key {
        "app.name" => Ok(minijinja::Value::from("My Application")),
        "app.version" => Ok(minijinja::Value::from("1.0.0")),
        _ => Ok(minijinja::Value::UNDEFINED),
    }
}
```

### Template Usage Examples
```jinja2
{# templates/emails/welcome.html #}
{% extends "emails/base.html" %}

{% block title %}Welcome to {{ config('app.name') }}!{% endblock %}

{% block content %}
<h1>Welcome, {{ user.firstName }}!</h1>

<p>Thank you for registering with {{ config('app.name') }}. Your account has been created successfully.</p>

<div class="user-details">
    <h2>Your Account Details:</h2>
    <ul>
        <li><strong>Username:</strong> {{ user.username }}</li>
        <li><strong>Email:</strong> {{ user.email }}</li>
        <li><strong>Registration Date:</strong> {{ user.createdAt | date_format("%B %d, %Y") }}</li>
    </ul>
</div>

<div class="next-steps">
    <h2>Next Steps:</h2>
    <ol>
        <li>Verify your email address by clicking the link below</li>
        <li>Complete your profile</li>
        <li>Explore our features</li>
    </ol>
</div>

<div class="action-button">
    <a href="{{ verificationUrl }}" class="btn btn-primary">Verify Email Address</a>
</div>

<p class="footer-note">
    If you have any questions, please contact our support team.
</p>
{% endblock %}
```

```jinja2
{# templates/notifications/order_status.html #}
{% extends "notifications/base.html" %}

{% block content %}
<div class="order-notification">
    <h1>Order Update</h1>

    <div class="order-summary">
        <h2>Order #{{ order.orderNumber }}</h2>
        <p><strong>Status:</strong> {{ order.status | title }}</p>
        <p><strong>Total:</strong> {{ order.totalAmount | currency }}</p>
        <p><strong>Order Date:</strong> {{ order.createdAt | date_format("%B %d, %Y") }}</p>
    </div>

    <div class="order-items">
        <h3>Items Ordered:</h3>
        <ul>
        {% for item in order.items %}
            <li>
                {{ item.productName }} -
                Quantity: {{ item.quantity }} -
                Price: {{ item.unitPrice | currency }}
            </li>
        {% endfor %}
        </ul>
    </div>

    {% if order.trackingNumber %}
    <div class="tracking-info">
        <h3>Tracking Information:</h3>
        <p>Your order is being shipped. Track your package: <strong>{{ order.trackingNumber }}</strong></p>
    </div>
    {% endif %}

    <div class="shipping-address">
        <h3>Shipping Address:</h3>
        <address>
            {{ order.shippingAddress.street }}<br>
            {{ order.shippingAddress.city }}, {{ order.shippingAddress.state }} {{ order.shippingAddress.zipCode }}<br>
            {{ order.shippingAddress.country }}
        </address>
    </div>
</div>
{% endblock %}
```

## 🔍 DATA TRANSFORMATION WITH JSONPATH

### JSONPath for Data Extraction
```rust
use jsonpath_rust::{JsonPathFinder, JsonPathQuery};
use serde_json::{Value, json};

pub struct DataTransformer {
    // Internal state
}

impl DataTransformer {
    pub fn extract_user_info(&self, api_response: &Value) -> Result<UserInfo, TransformError> {
        let finder = JsonPathFinder::from_str(api_response, "$.data.users[*]")?;
        let users: Vec<Value> = finder.find_slice();

        let mut user_infos = Vec::new();

        for user in users {
            let id = user.path("$.id")?.as_str()
                .ok_or(TransformError::MissingField("id"))?;
            let name = user.path("$.profile.fullName")?.as_str()
                .ok_or(TransformError::MissingField("fullName"))?;
            let email = user.path("$.contact.email")?.as_str()
                .ok_or(TransformError::MissingField("email"))?;

            user_infos.push(UserInfo {
                id: id.to_string(),
                name: name.to_string(),
                email: email.to_string(),
            });
        }

        Ok(user_infos)
    }

    pub fn extract_order_summary(&self, order_data: &Value) -> Result<OrderSummary, TransformError> {
        let order_id = order_data.path("$.order.id")?.as_str()
            .ok_or(TransformError::MissingField("order.id"))?;

        let customer_name = order_data.path("$.customer.profile.name")?.as_str()
            .ok_or(TransformError::MissingField("customer.name"))?;

        let total_amount = order_data.path("$.payment.total")?.as_f64()
            .ok_or(TransformError::MissingField("payment.total"))?;

        // Extract all item names
        let item_names: Vec<String> = order_data
            .path("$.items[*].product.name")?
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();

        Ok(OrderSummary {
            order_id: order_id.to_string(),
            customer_name: customer_name.to_string(),
            total_amount,
            item_names,
        })
    }

    pub fn build_notification_context(
        &self,
        user: &User,
        event_data: &Value,
    ) -> Result<NotificationContext, TransformError> {
        let event_type = event_data.path("$.type")?.as_str()
            .ok_or(TransformError::MissingField("type"))?;

        let timestamp = event_data.path("$.timestamp")?.as_str()
            .ok_or(TransformError::MissingField("timestamp"))?;

        // Extract event-specific data based on type
        let context_data = match event_type {
            "user_registration" => {
                json!({
                    "welcomeMessage": "Welcome to our platform!",
                    "nextSteps": ["Verify email", "Complete profile", "Explore features"]
                })
            },
            "order_confirmation" => {
                let order_number = event_data.path("$.data.orderNumber")?.as_str()
                    .ok_or(TransformError::MissingField("orderNumber"))?;
                json!({
                    "orderNumber": order_number,
                    "estimatedDelivery": event_data.path("$.data.estimatedDelivery")?,
                    "trackingUrl": format!("https://tracking.example.com/{}", order_number)
                })
            },
            "payment_failed" => {
                json!({
                    "errorMessage": event_data.path("$.data.error")?,
                    "retryUrl": "https://app.example.com/payment/retry",
                    "supportEmail": "support@example.com"
                })
            },
            _ => json!({}),
        };

        Ok(NotificationContext {
            user: user.clone(),
            event_type: event_type.to_string(),
            timestamp: timestamp.to_string(),
            data: context_data,
        })
    }
}

// Context structures for templates
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailContext {
    pub user: User,
    pub subject: String,
    pub verification_url: Option<String>,
    pub unsubscribe_url: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationContext {
    pub user: User,
    pub event_type: String,
    pub timestamp: String,
    pub data: Value,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderSummary {
    pub order_id: String,
    pub customer_name: String,
    pub total_amount: f64,
    pub item_names: Vec<String>,
}
```

## 🚨 TOOLS ANTI-PATTERNS

### What to Avoid
```rust
// ❌ Don't use env_logger
// use env_logger;
// env_logger::init();  // Use tracing instead

// ❌ Don't use TOML for complex configuration
// [server]
// host = "127.0.0.1"
// port = 8080
// [database]
// url = "postgresql://..."  // Use YAML instead

// ❌ Don't use Handlebars for templating
// use handlebars::Handlebars;
// let hbs = Handlebars::new();  // Use MiniJinja instead

// ❌ Don't put secrets in configuration files
// jwt_secret = "hardcoded-secret-key"  // Use environment variables

// ❌ Don't use println! for logging in production
// println!("User created: {}", user_id);  // Use tracing macros
```

## ✅ TOOLS AND CONFIG CHECKLIST

```markdown
### Tools and Configuration Verification
- [ ] Uses tracing ecosystem (not env_logger)
- [ ] YAML configuration files (not TOML for complex configs)
- [ ] Environment variable overrides for sensitive data
- [ ] Configuration validation on startup
- [ ] MiniJinja templating (not Handlebars)
- [ ] Custom filters and functions for templates
- [ ] JSONPath for complex data extraction
- [ ] Structured logging with spans and events
- [ ] File rotation for production logs
- [ ] Template inheritance and reusability
- [ ] Auto-escaping for security
- [ ] Context structures use camelCase serialization
```

This tools and configuration standard ensures robust, maintainable, and secure configuration and templating patterns for Rust applications.

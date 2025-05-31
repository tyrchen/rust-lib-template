---
description:
globs:
alwaysApply: false
---
# 🌐 AXUM WEB FRAMEWORK STANDARDS

> **TL;DR:** Comprehensive guidelines for building production-ready web applications with Axum, including AppConfig/AppState patterns, OpenAPI integration with utoipa, and scalable server architecture.

## 🏗️ AXUM APPLICATION ARCHITECTURE

```mermaid
graph TD
    HTTP["HTTP Requests"] --> Router["Axum Router"]
    Router --> Middleware["Middleware Stack"]
    Middleware --> Handlers["Route Handlers"]

    Handlers --> State["Application State"]
    State --> Config["AppConfig<br>(via arc-swap)"]
    State --> Database["Database Pool"]
    State --> Services["Service Layer"]

    Config --> Settings["Configuration Settings"]
    Database --> Repositories["Repository Layer"]
    Services --> BusinessLogic["Business Logic"]

    Handlers --> Response["HTTP Response"]
    Response --> OpenAPI["OpenAPI Docs<br>(utoipa)"]
    Response --> Swagger["Swagger UI"]

    style HTTP fill:#4da6ff,stroke:#0066cc,color:white
    style Router fill:#4dbb5f,stroke:#36873f,color:white
    style State fill:#ffa64d,stroke:#cc7a30,color:white
    style Config fill:#d94dbb,stroke:#a3378a,color:white
    style OpenAPI fill:#4dbbbb,stroke:#368787,color:white
```

## 🎯 AXUM VERSION AND SETUP

### Axum 0.8+ Requirements
- **Use Axum 0.8 or later** - leverages latest async patterns
- **Path parameters with `{param}` syntax** - more intuitive than `:param`
- **Structured router organization** - group related endpoints
- **OpenAPI integration** with utoipa for documentation
- **AppState pattern** with arc-swap for hot-reloadable configuration

## 📦 AXUM DEPENDENCIES

```toml
# Cargo.toml - Required dependencies for Axum applications
[dependencies]
# Core Axum
axum = { version = "0.8", features = ["macros", "multipart"] }
tokio = { version = "1.45", features = ["macros", "rt-multi-thread", "net", "fs", "time", "sync", "signal"] }
tower = { version = "0.5", features = ["full"] }
tower-http = { version = "0.6", features = ["cors", "trace", "compression", "auth", "limit"] }
http = "1.0"

# Configuration management with hot-reload
arc-swap = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# OpenAPI and documentation
utoipa = { version = "5.0", features = ["axum_extras", "chrono", "uuid"] }
utoipa-axum = "0.2"
utoipa-swagger-ui = { version = "9.0", features = ["axum"] }

# Error handling and validation
anyhow = "1.0"
thiserror = "2.0"
validator = { version = "0.18", features = ["derive"] }

# Utilities
uuid = { version = "1.17", features = ["v4", "v7", "serde"] }
chrono = { version = "0.4", features = ["serde"] }

# Logging and tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json", "chrono"] }

# Database (if needed)
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "postgres", "uuid", "chrono", "time", "json"] }

# HTTP client
reqwest = { version = "0.12", features = ["rustls-tls", "json", "stream", "multipart"] }

[dev-dependencies]
axum-test = "15.0"
tower-test = "0.4"
tempfile = "3.0"
wiremock = "0.6"
```

## 🔧 APPLICATION STATE PATTERN

### AppConfig with arc-swap

```rust
// src/config.rs
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

/// Application configuration that can be hot-reloaded
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub features: FeatureFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub cors_origins: Vec<String>,
    pub request_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_expiry_hours: u64,
    pub argon2_mem_cost: u32,
    pub argon2_time_cost: u32,
    pub argon2_parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FeatureFlags {
    pub enable_registration: bool,
    pub enable_swagger: bool,
    pub enable_metrics: bool,
}

impl AppConfig {
    pub fn load() -> anyhow::Result<Self> {
        // Load from environment variables, config files, etc.
        let config = Self {
            server: ServerConfig {
                host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: std::env::var("PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
                cors_origins: std::env::var("CORS_ORIGINS")
                    .unwrap_or_else(|_| "*".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                request_timeout_seconds: std::env::var("REQUEST_TIMEOUT")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()?,
            },
            database: DatabaseConfig {
                url: std::env::var("DATABASE_URL")
                    .expect("DATABASE_URL must be set"),
                max_connections: std::env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "20".to_string())
                    .parse()?,
                connection_timeout_seconds: std::env::var("DB_TIMEOUT")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()?,
            },
            auth: AuthConfig {
                jwt_secret: std::env::var("JWT_SECRET")
                    .expect("JWT_SECRET must be set"),
                token_expiry_hours: std::env::var("TOKEN_EXPIRY_HOURS")
                    .unwrap_or_else(|_| "24".to_string())
                    .parse()?,
                argon2_mem_cost: std::env::var("ARGON2_MEM_COST")
                    .unwrap_or_else(|_| "65536".to_string())
                    .parse()?,
                argon2_time_cost: std::env::var("ARGON2_TIME_COST")
                    .unwrap_or_else(|_| "3".to_string())
                    .parse()?,
                argon2_parallelism: std::env::var("ARGON2_PARALLELISM")
                    .unwrap_or_else(|_| "4".to_string())
                    .parse()?,
            },
            features: FeatureFlags {
                enable_registration: std::env::var("ENABLE_REGISTRATION")
                    .map(|v| v.parse().unwrap_or(true))
                    .unwrap_or(true),
                enable_swagger: std::env::var("ENABLE_SWAGGER")
                    .map(|v| v.parse().unwrap_or(false))
                    .unwrap_or(false),
                enable_metrics: std::env::var("ENABLE_METRICS")
                    .map(|v| v.parse().unwrap_or(false))
                    .unwrap_or(false),
            },
        };

        Ok(config)
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                cors_origins: vec!["*".to_string()],
                request_timeout_seconds: 30,
            },
            database: DatabaseConfig {
                url: "postgres://localhost/test".to_string(),
                max_connections: 20,
                connection_timeout_seconds: 30,
            },
            auth: AuthConfig {
                jwt_secret: "development-secret".to_string(),
                token_expiry_hours: 24,
                argon2_mem_cost: 65536,
                argon2_time_cost: 3,
                argon2_parallelism: 4,
            },
            features: FeatureFlags {
                enable_registration: true,
                enable_swagger: true,
                enable_metrics: false,
            },
        }
    }
}
```

### AppState Implementation

```rust
// src/state.rs
use crate::config::AppConfig;
use arc_swap::ArcSwap;
use sqlx::PgPool;
use std::sync::Arc;
use anyhow::Result;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// Configuration that can be hot-reloaded
    pub config: Arc<ArcSwap<AppConfig>>,
    /// Database connection pool
    pub db: PgPool,
    /// HTTP client for external APIs
    pub http_client: reqwest::Client,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self> {
        // Initialize database pool
        let db = PgPool::connect(&config.database.url).await?;

        // Run migrations
        sqlx::migrate!("./migrations").run(&db).await?;

        // Initialize HTTP client with timeout
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            db,
            http_client,
        })
    }

    /// Get current configuration
    pub fn config(&self) -> Arc<AppConfig> {
        self.config.load_full()
    }

    /// Update configuration (hot reload)
    pub fn update_config(&self, new_config: AppConfig) {
        self.config.store(Arc::new(new_config));
    }
}
```

## 🛣️ ROUTER AND ROUTES STRUCTURE

### Main Router Setup

```rust
// src/lib.rs
use axum::{
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    compression::CompressionLayer,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod config;
mod state;
mod routes;
mod middleware;
mod errors;

use state::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(
        routes::health::health_check,
        routes::auth::login,
        routes::auth::register,
        routes::users::get_user,
        routes::users::list_users,
        routes::products::list_products,
        routes::orders::create_order,
    ),
    components(
        schemas(
            config::AppConfig,
            config::ServerConfig,
            routes::auth::LoginRequest,
            routes::auth::RegisterRequest,
            routes::auth::TokenResponse,
            routes::users::User,
            routes::users::UserResponse,
            routes::products::Product,
            routes::orders::Order,
            errors::ApiError,
        )
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "auth", description = "Authentication endpoints"),
        (name = "users", description = "User management endpoints"),
        (name = "products", description = "Product catalog endpoints"),
        (name = "orders", description = "Order processing endpoints"),
    ),
    info(
        title = "My API",
        version = "1.0.0",
        description = "A well-documented API built with Axum",
        contact(
            name = "API Support",
            email = "support@example.com"
        )
    )
)]
struct ApiDoc;

pub async fn create_app(state: AppState) -> Router {
    let config = state.config();

    let mut router = Router::new()
        // Health endpoints
        .route("/health", get(routes::health::health_check))
        .route("/ready", get(routes::health::readiness_check))

        // API routes
        .nest("/api/v1", api_routes())

        // Add middleware
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(cors_layer(&config))

        // Add state
        .with_state(state);

    // Conditionally add Swagger UI
    if config.features.enable_swagger {
        router = router.merge(
            SwaggerUi::new("/swagger-ui")
                .url("/api-docs/openapi.json", ApiDoc::openapi())
        );
    }

    router
}

fn api_routes() -> Router<AppState> {
    Router::new()
        .nest("/auth", routes::auth::routes())
        .nest("/users", routes::users::routes())
        .nest("/products", routes::products::routes())
        .nest("/orders", routes::orders::routes())
        .layer(middleware::auth::auth_middleware())
}

fn cors_layer(config: &AppConfig) -> CorsLayer {
    let origins = config.server.cors_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect::<Vec<_>>();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
}
```

### Structured Router Pattern
```rust
use axum::{Router, routing::get, routing::post, extract::State};
use utoipa::OpenApi;
use std::sync::Arc;

#[derive(OpenApi)]
#[openapi(
    paths(
        users::list_users,
        users::get_user_by_id,
        users::create_user,
        users::update_user,
        users::delete_user,
        products::list_products,
        products::get_product_by_id,
        orders::create_order,
        orders::get_order_status,
    ),
    components(
        schemas(User, Product, Order, CreateUserRequest, UpdateUserRequest, ApiError)
    ),
    tags(
        (name = "users", description = "User management endpoints"),
        (name = "products", description = "Product catalog endpoints"),
        (name = "orders", description = "Order processing endpoints")
    )
)]
pub struct ApiDoc;

pub fn create_app(app_state: Arc<AppState>) -> Router {
    Router::new()
        .merge(create_api_router())
        .merge(create_docs_router())
        .with_state(app_state)
        .layer(create_middleware_stack())
}

fn create_api_router() -> Router<Arc<AppState>> {
    Router::new()
        .nest("/api/v1/users", users::create_router())
        .nest("/api/v1/products", products::create_router())
        .nest("/api/v1/orders", orders::create_router())
        .nest("/api/v1/health", health::create_router())
}

fn create_docs_router() -> Router<Arc<AppState>> {
    use utoipa_swagger_ui::SwaggerUi;

    Router::new()
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/api-docs/openapi.json", get(|| async {
            Json(ApiDoc::openapi())
        }))
}
```

### Module-based Endpoint Organization
```rust
// users.rs - User management endpoints
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

pub fn create_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/{user_id}", get(get_user_by_id).put(update_user).delete(delete_user))
        .route("/{user_id}/orders", get(get_user_orders))
}

#[derive(serde::Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ListUsersParams {
    #[param(minimum = 1, maximum = 100, default = 20)]
    pub limit: Option<i64>,
    #[param(minimum = 0, default = 0)]
    pub offset: Option<i64>,
    #[param(example = "john")]
    pub search: Option<String>,
    #[param(example = true)]
    pub active_only: Option<bool>,
}

#[utoipa::path(
    get,
    path = "/api/v1/users",
    params(ListUsersParams),
    responses(
        (status = 200, description = "List of users", body = [User]),
        (status = 500, description = "Internal server error", body = ApiError)
    ),
    tag = "users"
)]
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListUsersParams>,
) -> Result<Json<Vec<User>>, ApiError> {
    let limit = params.limit.unwrap_or(20);
    let offset = params.offset.unwrap_or(0);

    let mut query_builder = state.user_repository.query_builder();

    if let Some(search) = params.search {
        query_builder = query_builder.search(&search);
    }

    if params.active_only.unwrap_or(false) {
        query_builder = query_builder.active_only();
    }

    let users = query_builder
        .limit(limit)
        .offset(offset)
        .execute()
        .await
        .map_err(ApiError::from)?;

    Ok(Json(users))
}

#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User details", body = User),
        (status = 404, description = "User not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    ),
    tag = "users"
)]
pub async fn get_user_by_id(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<User>, ApiError> {
    let user = state
        .user_repository
        .find_by_id(user_id)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::NotFound("User not found".to_string()))?;

    Ok(Json(user))
}

#[utoipa::path(
    post,
    path = "/api/v1/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully", body = User),
        (status = 400, description = "Invalid request", body = ApiError),
        (status = 409, description = "User already exists", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    ),
    tag = "users"
)]
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    // Validate request
    state.validator.validate_create_user(&request).await?;

    // Check if user already exists
    if let Some(_) = state.user_repository.find_by_email(&request.email).await.map_err(ApiError::from)? {
        return Err(ApiError::Conflict("User with this email already exists".to_string()));
    }

    let user = state
        .user_repository
        .create(request)
        .await
        .map_err(ApiError::from)?;

    Ok((StatusCode::CREATED, Json(user)))
}
```

## 🔍 PATH AND QUERY PARAMETERS

### Path Parameter Patterns
```rust
// ✅ Good: Use {param} syntax (Axum 0.8+)
#[utoipa::path(
    get,
    path = "/api/v1/products/{product_id}/reviews/{review_id}",
    params(
        ("product_id" = Uuid, Path, description = "Product ID"),
        ("review_id" = Uuid, Path, description = "Review ID")
    ),
    responses(
        (status = 200, description = "Review details", body = ProductReview)
    ),
    tag = "products"
)]
pub async fn get_product_review(
    State(state): State<Arc<AppState>>,
    Path((product_id, review_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ProductReview>, ApiError> {
    let review = state
        .review_repository
        .find_by_product_and_id(product_id, review_id)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::NotFound("Review not found".to_string()))?;

    Ok(Json(review))
}

// ❌ Avoid: Old :param syntax
// .route("/products/:product_id/reviews/:review_id", get(get_product_review))
```

### Query Parameter Validation
```rust
#[derive(serde::Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ProductFilters {
    #[param(minimum = 0.01, example = 10.99)]
    pub min_price: Option<f64>,
    #[param(minimum = 0.01, example = 99.99)]
    pub max_price: Option<f64>,
    #[param(example = "electronics")]
    pub category: Option<String>,
    #[param(example = true)]
    pub in_stock: Option<bool>,
    #[param(inline, style = "form", explode = true)]
    pub tags: Option<Vec<String>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/products",
    params(ProductFilters),
    responses(
        (status = 200, description = "Filtered products", body = [Product])
    ),
    tag = "products"
)]
pub async fn list_products_with_filters(
    State(state): State<Arc<AppState>>,
    Query(filters): Query<ProductFilters>,
) -> Result<Json<Vec<Product>>, ApiError> {
    let products = state
        .product_repository
        .find_with_filters(&filters)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(products))
}
```

## 📝 REQUEST/RESPONSE HANDLING

### JSON Request Validation
```rust
use validator::{Validate, ValidationError};

#[derive(serde::Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrderRequest {
    #[validate(length(min = 1, message = "Customer ID is required"))]
    pub customer_id: String,

    #[validate(length(min = 1, message = "At least one item is required"))]
    pub items: Vec<OrderItem>,

    #[validate(range(min = 0.01, message = "Total amount must be positive"))]
    pub total_amount: f64,

    #[validate(email(message = "Invalid email format"))]
    pub contact_email: String,

    pub shipping_address: ShippingAddress,

    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(serde::Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrderItem {
    #[validate(length(min = 1, message = "Product ID is required"))]
    pub product_id: String,

    #[validate(range(min = 1, message = "Quantity must be at least 1"))]
    pub quantity: i32,

    #[validate(range(min = 0.01, message = "Price must be positive"))]
    pub unit_price: f64,
}

#[utoipa::path(
    post,
    path = "/api/v1/orders",
    request_body = CreateOrderRequest,
    responses(
        (status = 201, description = "Order created successfully", body = Order),
        (status = 400, description = "Validation error", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    ),
    tag = "orders"
)]
pub async fn create_order(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateOrderRequest>,
) -> Result<(StatusCode, Json<Order>), ApiError> {
    // Validate the request
    request.validate().map_err(ApiError::ValidationError)?;

    // Additional business validation
    state.order_validator.validate_order_request(&request).await?;

    // Create the order
    let order = state
        .order_repository
        .create(request)
        .await
        .map_err(ApiError::from)?;

    // Send confirmation email (async)
    tokio::spawn({
        let email_service = state.email_service.clone();
        let order_clone = order.clone();
        async move {
            if let Err(e) = email_service.send_order_confirmation(&order_clone).await {
                tracing::error!("Failed to send order confirmation: {}", e);
            }
        }
    });

    Ok((StatusCode::CREATED, Json(order)))
}
```

## 🔒 MIDDLEWARE IMPLEMENTATION

```rust
// src/middleware/auth.rs
use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use crate::{state::AppState, errors::ApiError};

pub fn auth_middleware() -> axum::middleware::FromFnLayer<
    fn(State<AppState>, Request, Next) -> impl std::future::Future<Output = Result<Response, ApiError>>,
    AppState,
> {
    axum::middleware::from_fn_with_state(auth_handler)
}

async fn auth_handler(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Skip auth for health endpoints
    if request.uri().path().starts_with("/health") ||
       request.uri().path().starts_with("/ready") ||
       request.uri().path().starts_with("/swagger-ui") {
        return Ok(next.run(request).await);
    }

    // Extract authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("Missing authorization header"))?;

    // Validate bearer token format
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::unauthorized("Invalid authorization format"))?;

    // Validate JWT token
    let user_id = validate_jwt_token(token, &state)?;

    // Add user ID to request extensions
    request.extensions_mut().insert(user_id);

    Ok(next.run(request).await)
}

fn validate_jwt_token(token: &str, state: &AppState) -> Result<String, ApiError> {
    // TODO: Implement actual JWT validation
    if token.starts_with("token_for_") {
        Ok("user123".to_string())
    } else {
        Err(ApiError::unauthorized("Invalid token"))
    }
}
```

## 🚨 ERROR HANDLING

### Centralized Error Types
```rust
// src/errors.rs
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: "BAD_REQUEST".to_string(),
            message: message.into(),
            details: None,
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            code: "UNAUTHORIZED".to_string(),
            message: message.into(),
            details: None,
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            code: "FORBIDDEN".to_string(),
            message: message.into(),
            details: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            code: "NOT_FOUND".to_string(),
            message: message.into(),
            details: None,
        }
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self {
            code: "INTERNAL_ERROR".to_string(),
            message: message.into(),
            details: None,
        }
    }

    pub fn validation_error(message: impl Into<String>) -> Self {
        Self {
            code: "VALIDATION_ERROR".to_string(),
            message: message.into(),
            details: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code.as_str() {
            "BAD_REQUEST" | "VALIDATION_ERROR" => StatusCode::BAD_REQUEST,
            "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
            "FORBIDDEN" => StatusCode::FORBIDDEN,
            "NOT_FOUND" => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, Json(self)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;

// Legacy error handling support
#[derive(thiserror::Error, Debug)]
pub enum LegacyApiError {
    #[error("Validation error: {0}")]
    ValidationError(#[from] validator::ValidationErrors),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<LegacyApiError> for ApiError {
    fn from(error: LegacyApiError) -> Self {
        match error {
            LegacyApiError::ValidationError(validation_errors) => {
                let details = serde_json::to_value(validation_errors).ok();
                Self {
                    code: "VALIDATION_ERROR".to_string(),
                    message: error.to_string(),
                    details,
                }
            }
            LegacyApiError::Database(db_error) => {
                tracing::error!("Database error: {}", db_error);
                Self::internal_error("Database error occurred")
            }
            LegacyApiError::NotFound(msg) => Self::not_found(msg),
            LegacyApiError::Conflict(msg) => Self {
                code: "CONFLICT".to_string(),
                message: msg,
                details: None,
            },
            LegacyApiError::Unauthorized(msg) => Self::unauthorized(msg),
            LegacyApiError::Forbidden(msg) => Self::forbidden(msg),
            LegacyApiError::BadRequest(msg) => Self::bad_request(msg),
            LegacyApiError::Internal(internal_error) => {
                tracing::error!("Internal error: {}", internal_error);
                Self::internal_error("Internal server error")
            }
        }
    }
}

impl IntoResponse for LegacyApiError {
    fn into_response(self) -> Response {
        let api_error: ApiError = self.into();
        api_error.into_response()
    }
}
            error: error_type.to_string(),
            message,
            details,
        });

        (status, body).into_response()
         }
}
```

## 🔑 AUTHENTICATION ROUTE HANDLERS

### Route Handlers with OpenAPI

```rust
// src/routes/auth.rs
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{post, Router},
};
use serde::{Deserialize, Serialize};
use utoipa::{ToSchema, IntoParams};
use validator::Validate;

use crate::{
    state::AppState,
    errors::{ApiError, Result},
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,

    #[validate(length(min = 2, message = "Name must be at least 2 characters"))]
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// User login endpoint
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = TokenResponse),
        (status = 400, description = "Invalid request", body = ApiError),
        (status = 401, description = "Invalid credentials", body = ApiError),
    ),
    tag = "auth"
)]
pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<TokenResponse>> {
    // Validate request
    request.validate()
        .map_err(|e| ApiError::validation_error(e.to_string()))?;

    // TODO: Implement actual authentication logic
    let token = generate_jwt_token(&request.email, &state)?;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: state.config().auth.token_expiry_hours * 3600,
    }))
}

/// User registration endpoint
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Registration successful", body = TokenResponse),
        (status = 400, description = "Invalid request", body = ApiError),
        (status = 409, description = "Email already exists", body = ApiError),
    ),
    tag = "auth"
)]
pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<TokenResponse>)> {
    // Check if registration is enabled
    if !state.config().features.enable_registration {
        return Err(ApiError::forbidden("Registration is disabled"));
    }

    // Validate request
    request.validate()
        .map_err(|e| ApiError::validation_error(e.to_string()))?;

    // TODO: Implement actual registration logic
    let token = generate_jwt_token(&request.email, &state)?;

    Ok((
        StatusCode::CREATED,
        Json(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: state.config().auth.token_expiry_hours * 3600,
        }),
    ))
}

fn generate_jwt_token(email: &str, state: &AppState) -> Result<String> {
    // TODO: Implement JWT token generation
    Ok(format!("token_for_{}", email))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use crate::config::AppConfig;

    #[tokio::test]
    async fn test_login_validation() {
        let state = AppState::new(AppConfig::default()).await.unwrap();
        let app = crate::create_app(state).await;
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({
                "email": "invalid-email",
                "password": "short"
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_valid_login() {
        let state = AppState::new(AppConfig::default()).await.unwrap();
        let app = crate::create_app(state).await;
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/api/v1/auth/login")
            .json(&LoginRequest {
                email: "test@example.com".to_string(),
                password: "validpassword".to_string(),
            })
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let token_response: TokenResponse = response.json();
        assert!(!token_response.access_token.is_empty());
        assert_eq!(token_response.token_type, "Bearer");
    }
}
```

## 🧪 INTEGRATION TESTING

### Axum Integration Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use serde_json::json;

    async fn create_test_app() -> TestServer {
        let app_state = Arc::new(create_test_app_state().await);
        let app = create_app(app_state);
        TestServer::new(app).unwrap()
    }

    #[tokio::test]
    async fn test_create_user_success() {
        let server = create_test_app().await;

        let request_body = json!({
            "username": "testuser",
            "email": "test@example.com",
            "fullName": "Test User"
        });

        let response = server
            .post("/api/v1/users")
            .json(&request_body)
            .await;

        response.assert_status_created();

        let user: User = response.json();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_create_user_validation_error() {
        let server = create_test_app().await;

        let request_body = json!({
            "username": "",  // Invalid: empty username
            "email": "invalid-email",  // Invalid: bad email format
        });

        let response = server
            .post("/api/v1/users")
            .json(&request_body)
            .await;

        response.assert_status_bad_request();

        let error: ErrorResponse = response.json();
        assert_eq!(error.error, "VALIDATION_ERROR");
    }

    #[tokio::test]
    async fn test_get_user_by_id() {
        let server = create_test_app().await;

        // Create a user first
        let create_response = server
            .post("/api/v1/users")
            .json(&json!({
                "username": "getuser",
                "email": "get@example.com",
                "fullName": "Get User"
            }))
            .await;

        let created_user: User = create_response.json();

        // Get the user by ID
        let get_response = server
            .get(&format!("/api/v1/users/{}", created_user.id))
            .await;

        get_response.assert_status_ok();

        let retrieved_user: User = get_response.json();
        assert_eq!(retrieved_user.id, created_user.id);
        assert_eq!(retrieved_user.username, "getuser");
    }

    #[tokio::test]
    async fn test_list_products_with_filters() {
        let server = create_test_app().await;

        let response = server
            .get("/api/v1/products")
            .add_query_param("minPrice", "10.00")
            .add_query_param("maxPrice", "50.00")
            .add_query_param("category", "electronics")
            .add_query_param("inStock", "true")
            .await;

        response.assert_status_ok();

        let products: Vec<Product> = response.json();
        for product in products {
            assert!(product.price >= 10.0 && product.price <= 50.0);
            assert_eq!(product.category, "electronics");
            assert!(product.in_stock);
        }
    }

    #[tokio::test]
    async fn test_create_order_flow() {
        let server = create_test_app().await;

        let request_body = json!({
            "customerId": "customer-123",
            "items": [
                {
                    "productId": "product-1",
                    "quantity": 2,
                    "unitPrice": 29.99
                },
                {
                    "productId": "product-2",
                    "quantity": 1,
                    "unitPrice": 15.50
                }
            ],
            "totalAmount": 75.48,
            "contactEmail": "customer@example.com",
            "shippingAddress": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zipCode": "12345",
                "country": "US"
            },
            "notes": "Please handle with care"
        });

        let response = server
            .post("/api/v1/orders")
            .json(&request_body)
            .await;

        response.assert_status_created();

        let order: Order = response.json();
        assert_eq!(order.customer_id, "customer-123");
        assert_eq!(order.items.len(), 2);
        assert_eq!(order.total_amount, 75.48);
        assert_eq!(order.status, OrderStatus::Pending);
    }
}
```

## 🚨 AXUM ANTI-PATTERNS

### What to Avoid
```rust
// ❌ Don't use old path parameter syntax
// .route("/users/:id", get(get_user))  // Use {id} instead

// ❌ Don't forget error handling
// pub async fn get_user(Path(id): Path<String>) -> Json<User> {
//     let user = repository.find(id).await.unwrap();  // No error handling
//     Json(user)
// }

// ❌ Don't skip request validation
// pub async fn create_user(Json(request): Json<CreateUserRequest>) -> Json<User> {
//     // No validation of the request
// }

// ❌ Don't use blocking operations in handlers
// pub async fn bad_handler() -> String {
//     std::thread::sleep(Duration::from_secs(5));  // Blocks entire runtime
//     "response".to_string()
// }

// ❌ Don't forget OpenAPI documentation
// pub async fn undocumented_endpoint() -> String {
//     // Missing #[utoipa::path] annotation
//     "response".to_string()
// }
```

## 📝 AXUM BEST PRACTICES CHECKLIST

```markdown
## Axum Implementation Verification

### Configuration Management
- [ ] AppConfig struct with proper serialization
- [ ] arc-swap used for hot-reloadable config
- [ ] Environment variable loading implemented
- [ ] Default configuration provided

### Application State
- [ ] AppState contains all shared resources
- [ ] Database pool properly initialized
- [ ] HTTP client configured with timeouts
- [ ] State passed to all route handlers

### OpenAPI Integration
- [ ] utoipa derives added to all request/response types
- [ ] API paths documented with #[utoipa::path]
- [ ] OpenAPI struct defined with proper metadata
- [ ] Swagger UI conditionally enabled

### Route Organization
- [ ] Routes organized by feature modules
- [ ] Proper HTTP methods used (GET, POST, PUT, DELETE)
- [ ] Uses Axum 0.8+ with {param} path syntax
- [ ] Request/response types properly defined
- [ ] Path and query parameter validation

### Middleware
- [ ] Authentication middleware implemented
- [ ] CORS layer configured appropriately
- [ ] Tracing layer for request logging
- [ ] Compression middleware for responses
- [ ] Rate limiting configured if needed

### Error Handling
- [ ] Structured error types with proper HTTP status codes
- [ ] IntoResponse trait implemented for errors
- [ ] Consistent error format across API
- [ ] Proper error logging implemented
- [ ] Validation errors properly handled

### Request/Response Handling
- [ ] All data structures use #[serde(rename_all = "camelCase")]
- [ ] Request validation using validator crate
- [ ] Proper content-type handling
- [ ] Response status codes follow HTTP standards
- [ ] JSON serialization configured correctly

### Testing
- [ ] Unit tests for handlers
- [ ] Integration tests with TestServer
- [ ] Request/response validation tests
- [ ] Authentication middleware tests
- [ ] Error handling tests

### Security
- [ ] JWT token validation implemented
- [ ] Bearer token format enforced
- [ ] Authorization headers required
- [ ] CORS origins properly configured
- [ ] Input validation on all endpoints

### Performance
- [ ] No blocking operations in async handlers
- [ ] Database connection pooling
- [ ] HTTP client connection reuse
- [ ] Response compression enabled
- [ ] Appropriate timeout configurations
```

This comprehensive Axum standard ensures production-ready, secure, and maintainable web APIs with modern Rust practices.

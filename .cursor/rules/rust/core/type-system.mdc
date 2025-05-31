---
description:
globs:
alwaysApply: false
---
# 🔍 RUST TYPE SYSTEM BEST PRACTICES

> **TL;DR:** Leverage Rust's powerful type system for safety, performance, and expressiveness through newtype patterns, phantom types, and zero-cost abstractions.

## 🔍 TYPE SYSTEM DESIGN STRATEGY

```mermaid
graph TD
    Start["Type Design"] --> DomainCheck{"Domain-Specific<br>Types Needed?"}

    DomainCheck -->|Yes| NewtypePattern["Newtype Pattern"]
    DomainCheck -->|No| PrimitiveCheck{"Primitive<br>Obsession?"}

    NewtypePattern --> StateTracking{"State Tracking<br>Required?"}
    PrimitiveCheck -->|Yes| NewtypePattern
    PrimitiveCheck -->|No| TraitDesign["Trait Design"]

    StateTracking -->|Yes| PhantomTypes["Phantom Types"]
    StateTracking -->|No| ValidatedTypes["Validated Types"]

    PhantomTypes --> CompileTimeCheck["Compile-Time Validation"]
    ValidatedTypes --> RuntimeCheck["Runtime Validation"]

    CompileTimeCheck --> ZeroCost["Zero-Cost Abstractions"]
    RuntimeCheck --> ZeroCost
    TraitDesign --> ZeroCost

    ZeroCost --> ErrorModeling["Error Modeling"]
    ErrorModeling --> SafetyPatterns["Safety Patterns"]
    SafetyPatterns --> Performance["Performance Optimization"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style NewtypePattern fill:#4dbb5f,stroke:#36873f,color:white
    style PhantomTypes fill:#ffa64d,stroke:#cc7a30,color:white
    style ZeroCost fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 TYPE SAFETY PRINCIPLES

### Newtype Pattern for Domain Modeling
```rust
use derive_more::{Constructor, Display, From, Into};
use serde::{Deserialize, Serialize};
use std::fmt;

// ✅ Strong typing for domain concepts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Constructor, Display, From, Into)]
pub struct UserId(uuid::Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Constructor, Display, From, Into)]
pub struct ProductId(uuid::Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Constructor, Display, From, Into)]
pub struct OrderId(uuid::Uuid);

// ✅ Prevents mixing up IDs at compile time
fn process_order(user_id: UserId, product_id: ProductId) -> OrderId {
    // Compiler prevents: process_order(product_id, user_id)
    OrderId(uuid::Uuid::new_v4())
}

// ❌ Weak typing - prone to errors
// fn process_order(user_id: String, product_id: String) -> String
```

### Validated Types with Builder Pattern
```rust
use typed_builder::TypedBuilder;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, TypedBuilder, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Email {
    #[validate(email)]
    #[builder(setter(into))]
    value: String,
}

impl Email {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let email = Self { value: value.into() };
        email.validate()?;
        Ok(email)
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ✅ Usage - compile-time guarantee of valid email
let email = Email::new("user@example.com")?;
```

### Phantom Types for Compile-Time State
```rust
use std::marker::PhantomData;

// State types
pub struct Draft;
pub struct Published;
pub struct Archived;

// Document with compile-time state tracking
#[derive(Debug, Clone)]
pub struct Document<State> {
    id: DocumentId,
    title: String,
    content: String,
    _state: PhantomData<State>,
}

impl<State> Document<State> {
    pub fn id(&self) -> DocumentId {
        self.id
    }

    pub fn title(&self) -> &str {
        &self.title
    }
}

impl Document<Draft> {
    pub fn new(title: String, content: String) -> Self {
        Self {
            id: DocumentId::new(),
            title,
            content,
            _state: PhantomData,
        }
    }

    pub fn publish(self) -> Document<Published> {
        Document {
            id: self.id,
            title: self.title,
            content: self.content,
            _state: PhantomData,
        }
    }
}

impl Document<Published> {
    pub fn archive(self) -> Document<Archived> {
        Document {
            id: self.id,
            title: self.title,
            content: self.content,
            _state: PhantomData,
        }
    }

    pub fn content(&self) -> &str {
        &self.content
    }
}

impl Document<Archived> {
    pub fn restore(self) -> Document<Draft> {
        Document {
            id: self.id,
            title: self.title,
            content: self.content,
            _state: PhantomData,
        }
    }
}

// ✅ Usage - compiler prevents invalid state transitions
let draft = Document::<Draft>::new("Title".to_string(), "Content".to_string());
let published = draft.publish();
let archived = published.archive();
// Compiler error: draft.archive() - can't archive a draft
```

## 🔄 TRAIT DESIGN PATTERNS

### Trait Objects vs Generic Bounds
```rust
// ✅ Use generics for known types at compile time
pub fn process_items<T: Processable>(items: &[T]) -> Vec<T::Output> {
    items.iter().map(|item| item.process()).collect()
}

// ✅ Use trait objects for runtime polymorphism
pub struct EventBus {
    handlers: Vec<Box<dyn EventHandler>>,
}

impl EventBus {
    pub fn register_handler(&mut self, handler: Box<dyn EventHandler>) {
        self.handlers.push(handler);
    }

    pub fn dispatch(&self, event: &Event) {
        for handler in &self.handlers {
            handler.handle(event);
        }
    }
}

// ✅ Async trait pattern
#[async_trait::async_trait]
pub trait AsyncProcessor {
    type Error;
    type Output;

    async fn process(&self, input: &[u8]) -> Result<Self::Output, Self::Error>;
}
```

### Associated Types vs Generic Parameters
```rust
// ✅ Use associated types for tight coupling
pub trait Iterator {
    type Item;  // One Item type per Iterator implementation
    fn next(&mut self) -> Option<Self::Item>;
}

// ✅ Use generic parameters for flexibility
pub trait Convert<T, U> {
    fn convert(&self, input: T) -> U;
}

// Example: A single type can implement multiple conversions
impl Convert<String, i32> for NumberParser {
    fn convert(&self, input: String) -> i32 { /* ... */ }
}

impl Convert<String, f64> for NumberParser {
    fn convert(&self, input: String) -> f64 { /* ... */ }
}
```

## 📊 ENUM DESIGN PATTERNS

### Comprehensive Error Modeling
```rust
#[derive(thiserror::Error, Debug)]
pub enum UserServiceError {
    #[error("User not found: {user_id}")]
    NotFound { user_id: UserId },

    #[error("Email already exists: {email}")]
    EmailExists { email: Email },

    #[error("Database error: {source}")]
    Database {
        #[from]
        source: sqlx::Error,
    },

    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("Permission denied: {action} requires {permission}")]
    PermissionDenied {
        action: String,
        permission: String,
    },
}

// ✅ Structured error handling with context
impl UserServiceError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Database { .. })
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "USER_NOT_FOUND",
            Self::EmailExists { .. } => "EMAIL_EXISTS",
            Self::Database { .. } => "DATABASE_ERROR",
            Self::Validation { .. } => "VALIDATION_ERROR",
            Self::PermissionDenied { .. } => "PERMISSION_DENIED",
        }
    }
}
```

### State Machine with Enums
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "camelCase")]
pub enum OrderStatus {
    Pending { items: Vec<OrderItem> },
    Processing { estimated_completion: DateTime<Utc> },
    Shipped { tracking_number: String, carrier: String },
    Delivered { delivery_time: DateTime<Utc> },
    Cancelled { reason: String, refund_issued: bool },
}

impl OrderStatus {
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Pending { .. } | Self::Processing { .. })
    }

    pub fn can_ship(&self) -> bool {
        matches!(self, Self::Processing { .. })
    }

    pub fn is_final(&self) -> bool {
        matches!(self, Self::Delivered { .. } | Self::Cancelled { .. })
    }
}

// ✅ Type-safe state transitions
impl Order {
    pub fn ship(mut self, tracking_number: String, carrier: String) -> Result<Self, OrderError> {
        match self.status {
            OrderStatus::Processing { .. } => {
                self.status = OrderStatus::Shipped { tracking_number, carrier };
                Ok(self)
            }
            _ => Err(OrderError::InvalidStateTransition {
                from: self.status.clone(),
                to: "Shipped".to_string(),
            }),
        }
    }
}
```

## 🛡️ SAFETY PATTERNS

### Option and Result Combinators
```rust
// ✅ Chain operations safely
fn process_user_data(user_id: UserId) -> Result<ProcessedData, ServiceError> {
    find_user(user_id)?
        .and_then(|user| user.profile.as_ref().ok_or(ServiceError::MissingProfile))
        .and_then(|profile| validate_profile(profile))
        .map(|profile| process_profile(profile))
}

// ✅ Use combinators for cleaner code
fn get_user_email(user_id: UserId) -> Option<Email> {
    find_user(user_id)
        .ok()
        .and_then(|user| user.email)
        .filter(|email| email.is_verified())
}

// ✅ Error conversion with context
fn create_user(request: CreateUserRequest) -> Result<User, UserServiceError> {
    validate_email(&request.email)
        .map_err(|e| UserServiceError::Validation { message: e.to_string() })?;

    repository
        .create_user(request)
        .await
        .map_err(UserServiceError::from)
}
```

### Custom Smart Pointers
```rust
use std::ops::{Deref, DerefMut};

// ✅ Validated wrapper that maintains invariants
#[derive(Debug)]
pub struct NonEmptyVec<T> {
    inner: Vec<T>,
}

impl<T> NonEmptyVec<T> {
    pub fn new(first: T) -> Self {
        Self {
            inner: vec![first],
        }
    }

    pub fn try_from_vec(vec: Vec<T>) -> Result<Self, EmptyVecError> {
        if vec.is_empty() {
            Err(EmptyVecError)
        } else {
            Ok(Self { inner: vec })
        }
    }

    pub fn push(&mut self, item: T) {
        self.inner.push(item);
    }

    pub fn first(&self) -> &T {
        // Safe to unwrap because we maintain the non-empty invariant
        self.inner.first().unwrap()
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
```

## 🎨 ZERO-COST ABSTRACTIONS

### Compile-Time Constants
```rust
// ✅ Use const generics for compile-time validation
#[derive(Debug, Clone)]
pub struct FixedArray<T, const N: usize> {
    data: [T; N],
}

impl<T: Default + Copy, const N: usize> FixedArray<T, N> {
    pub fn new() -> Self {
        Self {
            data: [T::default(); N],
        }
    }
}

// ✅ Type-level programming with const generics
pub struct Matrix<T, const ROWS: usize, const COLS: usize> {
    data: [[T; COLS]; ROWS],
}

impl<T, const ROWS: usize, const COLS: usize> Matrix<T, ROWS, COLS> {
    pub fn multiply<const OTHER_COLS: usize>(
        self,
        other: Matrix<T, COLS, OTHER_COLS>,
    ) -> Matrix<T, ROWS, OTHER_COLS>
    where
        T: Default + Copy + std::ops::Add<Output = T> + std::ops::Mul<Output = T>,
    {
        // Matrix multiplication with compile-time dimension checking
        todo!()
    }
}
```

### Builder with Type State
```rust
// ✅ Builder pattern with compile-time validation
pub struct ConfigBuilder<HasHost, HasPort> {
    host: Option<String>,
    port: Option<u16>,
    timeout: Option<Duration>,
    _marker: PhantomData<(HasHost, HasPort)>,
}

pub struct Missing;
pub struct Present;

impl ConfigBuilder<Missing, Missing> {
    pub fn new() -> Self {
        Self {
            host: None,
            port: None,
            timeout: None,
            _marker: PhantomData,
        }
    }
}

impl<HasPort> ConfigBuilder<Missing, HasPort> {
    pub fn host(self, host: String) -> ConfigBuilder<Present, HasPort> {
        ConfigBuilder {
            host: Some(host),
            port: self.port,
            timeout: self.timeout,
            _marker: PhantomData,
        }
    }
}

impl<HasHost> ConfigBuilder<HasHost, Missing> {
    pub fn port(self, port: u16) -> ConfigBuilder<HasHost, Present> {
        ConfigBuilder {
            host: self.host,
            port: Some(port),
            timeout: self.timeout,
            _marker: PhantomData,
        }
    }
}

impl<HasHost, HasPort> ConfigBuilder<HasHost, HasPort> {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

// Only allow build when both host and port are set
impl ConfigBuilder<Present, Present> {
    pub fn build(self) -> Config {
        Config {
            host: self.host.unwrap(),
            port: self.port.unwrap(),
            timeout: self.timeout.unwrap_or(Duration::from_secs(30)),
        }
    }
}

// ✅ Usage - compiler ensures required fields
let config = ConfigBuilder::new()
    .host("localhost".to_string())
    .port(8080)
    .timeout(Duration::from_secs(60))
    .build();
```

## 🚨 TYPE SYSTEM ANTI-PATTERNS

### What to Avoid
```rust
// ❌ Weak typing - error prone
fn calculate_discount(price: f64, percentage: f64) -> f64 {
    // Could accidentally pass percentage as price
    price * (percentage / 100.0)
}

// ✅ Strong typing prevents errors
#[derive(Debug, Clone, Copy)]
pub struct Price(f64);

#[derive(Debug, Clone, Copy)]
pub struct Percentage(f64);

fn calculate_discount(price: Price, percentage: Percentage) -> Price {
    Price(price.0 * (percentage.0 / 100.0))
}

// ❌ Overuse of String for everything
// struct User {
//     id: String,
//     email: String,
//     status: String,
// }

// ✅ Proper typing
struct User {
    id: UserId,
    email: Email,
    status: UserStatus,
}

// ❌ Large enums with mixed concerns
// enum AppState {
//     Loading,
//     UserData(User),
//     Error(String),
//     DatabaseConnection(Database),
//     HttpRequest(Request),
// }

// ✅ Focused enums
enum LoadingState {
    Loading,
    Loaded(User),
    Failed(LoadError),
}
```

## ✅ TYPE SYSTEM CHECKLIST

```markdown
### Type System Implementation Verification
- [ ] Uses newtype pattern for domain concepts
- [ ] Phantom types for compile-time state tracking
- [ ] Associated types vs generics chosen appropriately
- [ ] Enums model state machines correctly
- [ ] Option/Result combinators used over unwrap
- [ ] Zero-cost abstractions leverage compile-time checks
- [ ] Builder patterns enforce required fields
- [ ] Error types are structured and informative
- [ ] No primitive obsession (avoid String/i32 for everything)
- [ ] Type safety prevents common runtime errors
- [ ] Const generics used for compile-time validation
- [ ] Trait objects vs generics chosen appropriately
```

This type system guide leverages Rust's powerful type system to catch errors at compile time and create more maintainable, expressive code.

---
description:
globs:
alwaysApply: false
---
# 🎭 RUST DESIGN PATTERNS

> **TL;DR:** Essential design patterns for Rust applications, focusing on idiomatic solutions that leverage Rust's ownership system and zero-cost abstractions.

## 🔍 DESIGN PATTERN SELECTION STRATEGY

```mermaid
graph TD
    Start["Design Challenge"] --> ProblemType{"Problem<br>Category?"}

    ProblemType -->|Object Creation| Creational["Creational Patterns"]
    ProblemType -->|Object Behavior| Behavioral["Behavioral Patterns"]
    ProblemType -->|Object Structure| Structural["Structural Patterns"]
    ProblemType -->|Concurrency| ConcurrencyP["Concurrency Patterns"]

    Creational --> BuilderCheck{"Complex<br>Configuration?"}
    Creational --> FactoryCheck{"Multiple<br>Implementations?"}

    BuilderCheck -->|Yes| TypeStateBuilder["Type-State Builder"]
    FactoryCheck -->|Yes| AbstractFactory["Abstract Factory"]

    Behavioral --> StrategyCheck{"Runtime Algorithm<br>Selection?"}
    Behavioral --> CommandCheck{"Undo/Redo<br>Required?"}
    Behavioral --> ObserverCheck{"Event-Driven<br>Architecture?"}

    StrategyCheck -->|Yes| StrategyPattern["Strategy Pattern"]
    CommandCheck -->|Yes| CommandPattern["Command Pattern"]
    ObserverCheck -->|Yes| ObserverPattern["Observer Pattern"]

    Structural --> AdapterCheck{"External API<br>Integration?"}
    Structural --> DecoratorCheck{"Cross-Cutting<br>Concerns?"}

    AdapterCheck -->|Yes| AdapterPattern["Adapter Pattern"]
    DecoratorCheck -->|Yes| DecoratorPattern["Decorator Pattern"]

    ConcurrencyP --> ActorCheck{"Isolated State<br>Management?"}
    ConcurrencyP --> PipelineCheck{"Data Pipeline<br>Processing?"}

    ActorCheck -->|Yes| ActorPattern["Actor Pattern"]
    PipelineCheck -->|Yes| PipelinePattern["Pipeline Pattern"]

    TypeStateBuilder --> Implementation["Implementation"]
    AbstractFactory --> Implementation
    StrategyPattern --> Implementation
    CommandPattern --> Implementation
    ObserverPattern --> Implementation
    AdapterPattern --> Implementation
    DecoratorPattern --> Implementation
    ActorPattern --> Implementation
    PipelinePattern --> Implementation

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style Creational fill:#4dbb5f,stroke:#36873f,color:white
    style Behavioral fill:#ffa64d,stroke:#cc7a30,color:white
    style Structural fill:#d94dbb,stroke:#a3378a,color:white
    style ConcurrencyP fill:#9d4dbb,stroke:#7a3a8a,color:white
```

## 🏗️ CREATIONAL PATTERNS

### Builder Pattern with Type State
```rust
use std::marker::PhantomData;

// ✅ Type-safe builder preventing invalid configurations
pub struct DatabaseConfigBuilder<HasHost, HasPort, HasDatabase> {
    host: Option<String>,
    port: Option<u16>,
    database: Option<String>,
    username: Option<String>,
    password: Option<String>,
    _marker: PhantomData<(HasHost, HasPort, HasDatabase)>,
}

pub struct Missing;
pub struct Present;

impl DatabaseConfigBuilder<Missing, Missing, Missing> {
    pub fn new() -> Self {
        Self {
            host: None,
            port: None,
            database: None,
            username: None,
            password: None,
            _marker: PhantomData,
        }
    }
}

impl<HasPort, HasDatabase> DatabaseConfigBuilder<Missing, HasPort, HasDatabase> {
    pub fn host(self, host: impl Into<String>) -> DatabaseConfigBuilder<Present, HasPort, HasDatabase> {
        DatabaseConfigBuilder {
            host: Some(host.into()),
            port: self.port,
            database: self.database,
            username: self.username,
            password: self.password,
            _marker: PhantomData,
        }
    }
}

impl<HasHost, HasDatabase> DatabaseConfigBuilder<HasHost, Missing, HasDatabase> {
    pub fn port(self, port: u16) -> DatabaseConfigBuilder<HasHost, Present, HasDatabase> {
        DatabaseConfigBuilder {
            host: self.host,
            port: Some(port),
            database: self.database,
            username: self.username,
            password: self.password,
            _marker: PhantomData,
        }
    }
}

impl<HasHost, HasPort> DatabaseConfigBuilder<HasHost, HasPort, Missing> {
    pub fn database(self, database: impl Into<String>) -> DatabaseConfigBuilder<HasHost, HasPort, Present> {
        DatabaseConfigBuilder {
            host: self.host,
            port: self.port,
            database: Some(database.into()),
            username: self.username,
            password: self.password,
            _marker: PhantomData,
        }
    }
}

impl<HasHost, HasPort, HasDatabase> DatabaseConfigBuilder<HasHost, HasPort, HasDatabase> {
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }
}

// Only allow building when all required fields are present
impl DatabaseConfigBuilder<Present, Present, Present> {
    pub fn build(self) -> DatabaseConfig {
        DatabaseConfig {
            host: self.host.unwrap(),
            port: self.port.unwrap(),
            database: self.database.unwrap(),
            username: self.username,
            password: self.password,
        }
    }
}

// ✅ Usage - compiler enforces required fields
let config = DatabaseConfigBuilder::new()
    .host("localhost")
    .port(5432)
    .database("myapp")
    .username("admin")
    .build();
```

### Factory Pattern with Associated Types
```rust
// ✅ Factory pattern for creating different database connections
pub trait ConnectionFactory {
    type Connection;
    type Config;
    type Error;

    fn create_connection(config: Self::Config) -> Result<Self::Connection, Self::Error>;
    fn connection_type() -> &'static str;
}

pub struct PostgresFactory;
pub struct SqliteFactory;

impl ConnectionFactory for PostgresFactory {
    type Connection = sqlx::PgPool;
    type Config = PostgresConfig;
    type Error = sqlx::Error;

    fn create_connection(config: Self::Config) -> Result<Self::Connection, Self::Error> {
        // Implementation
    }

    fn connection_type() -> &'static str {
        "PostgreSQL"
    }
}

impl ConnectionFactory for SqliteFactory {
    type Connection = sqlx::SqlitePool;
    type Config = SqliteConfig;
    type Error = sqlx::Error;

    fn create_connection(config: Self::Config) -> Result<Self::Connection, Self::Error> {
        // Implementation
    }

    fn connection_type() -> &'static str {
        "SQLite"
    }
}

// ✅ Generic database service using factory
pub struct DatabaseService<F: ConnectionFactory> {
    connection: F::Connection,
    _factory: PhantomData<F>,
}

impl<F: ConnectionFactory> DatabaseService<F> {
    pub fn new(config: F::Config) -> Result<Self, F::Error> {
        let connection = F::create_connection(config)?;
        Ok(Self {
            connection,
            _factory: PhantomData,
        })
    }

    pub fn connection_info(&self) -> &'static str {
        F::connection_type()
    }
}
```

## 🔄 BEHAVIORAL PATTERNS

### Strategy Pattern with Enums
```rust
// ✅ Strategy pattern for different authentication methods
#[derive(Debug, Clone)]
pub enum AuthStrategy {
    Bearer { token: String },
    ApiKey { key: String, header: String },
    Basic { username: String, password: String },
    OAuth2 { client_id: String, client_secret: String },
}

impl AuthStrategy {
    pub fn apply_to_request(&self, request: &mut Request) -> Result<(), AuthError> {
        match self {
            AuthStrategy::Bearer { token } => {
                request.headers_mut().insert(
                    "Authorization",
                    format!("Bearer {}", token).parse().unwrap(),
                );
            }
            AuthStrategy::ApiKey { key, header } => {
                request.headers_mut().insert(
                    header.as_str(),
                    key.parse().unwrap(),
                );
            }
            AuthStrategy::Basic { username, password } => {
                let encoded = base64::encode(format!("{}:{}", username, password));
                request.headers_mut().insert(
                    "Authorization",
                    format!("Basic {}", encoded).parse().unwrap(),
                );
            }
            AuthStrategy::OAuth2 { client_id, client_secret } => {
                // OAuth2 implementation
                self.handle_oauth2(request, client_id, client_secret)?;
            }
        }
        Ok(())
    }

    fn handle_oauth2(&self, request: &mut Request, client_id: &str, client_secret: &str) -> Result<(), AuthError> {
        // OAuth2 token exchange logic
        todo!()
    }
}

// ✅ Context that uses the strategy
pub struct HttpClient {
    client: reqwest::Client,
    auth_strategy: Option<AuthStrategy>,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            auth_strategy: None,
        }
    }

    pub fn with_auth(mut self, strategy: AuthStrategy) -> Self {
        self.auth_strategy = Some(strategy);
        self
    }

    pub async fn request(&self, url: &str) -> Result<Response, HttpError> {
        let mut request = self.client.get(url).build()?;

        if let Some(ref auth) = self.auth_strategy {
            auth.apply_to_request(&mut request)?;
        }

        let response = self.client.execute(request).await?;
        Ok(response)
    }
}
```

### Command Pattern with Undo
```rust
// ✅ Command pattern for operations with undo capability
pub trait Command {
    type Error;

    fn execute(&mut self) -> Result<(), Self::Error>;
    fn undo(&mut self) -> Result<(), Self::Error>;
    fn description(&self) -> &str;
}

#[derive(Debug)]
pub struct CreateUserCommand {
    user_service: Arc<UserService>,
    user_data: User,
    created_user_id: Option<UserId>,
}

impl CreateUserCommand {
    pub fn new(user_service: Arc<UserService>, user_data: User) -> Self {
        Self {
            user_service,
            user_data,
            created_user_id: None,
        }
    }
}

impl Command for CreateUserCommand {
    type Error = UserServiceError;

    fn execute(&mut self) -> Result<(), Self::Error> {
        let user = self.user_service.create_user(&self.user_data)?;
        self.created_user_id = Some(user.id);
        Ok(())
    }

    fn undo(&mut self) -> Result<(), Self::Error> {
        if let Some(user_id) = self.created_user_id.take() {
            self.user_service.delete_user(user_id)?;
        }
        Ok(())
    }

    fn description(&self) -> &str {
        "Create user"
    }
}

// ✅ Command invoker with history
pub struct CommandHistory {
    executed_commands: Vec<Box<dyn Command<Error = Box<dyn std::error::Error>>>>,
    current_position: usize,
}

impl CommandHistory {
    pub fn new() -> Self {
        Self {
            executed_commands: Vec::new(),
            current_position: 0,
        }
    }

    pub fn execute<C>(&mut self, mut command: C) -> Result<(), C::Error>
    where
        C: Command + 'static,
        C::Error: Into<Box<dyn std::error::Error>>,
    {
        command.execute()?;

        // Remove any commands after current position (when redoing after undo)
        self.executed_commands.truncate(self.current_position);

        // Add the new command
        self.executed_commands.push(Box::new(command));
        self.current_position += 1;

        Ok(())
    }

    pub fn undo(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.current_position > 0 {
            self.current_position -= 1;
            self.executed_commands[self.current_position].undo()?;
        }
        Ok(())
    }

    pub fn redo(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.current_position < self.executed_commands.len() {
            self.executed_commands[self.current_position].execute()?;
            self.current_position += 1;
        }
        Ok(())
    }
}
```

### Observer Pattern with Async
```rust
use tokio::sync::broadcast;

// ✅ Event-driven observer pattern with async support
#[derive(Debug, Clone)]
pub enum DomainEvent {
    UserCreated { user_id: UserId, email: String },
    UserUpdated { user_id: UserId, changes: Vec<String> },
    UserDeleted { user_id: UserId },
    OrderPlaced { order_id: OrderId, user_id: UserId, amount: Decimal },
}

#[async_trait::async_trait]
pub trait EventHandler {
    async fn handle(&self, event: &DomainEvent) -> Result<(), EventError>;
    fn interested_in(&self) -> Vec<std::mem::Discriminant<DomainEvent>>;
}

pub struct EmailNotificationHandler {
    email_service: Arc<EmailService>,
}

#[async_trait::async_trait]
impl EventHandler for EmailNotificationHandler {
    async fn handle(&self, event: &DomainEvent) -> Result<(), EventError> {
        match event {
            DomainEvent::UserCreated { email, .. } => {
                self.email_service.send_welcome_email(email).await?;
            }
            DomainEvent::OrderPlaced { user_id, amount, .. } => {
                let user = self.get_user(*user_id).await?;
                self.email_service.send_order_confirmation(&user.email, *amount).await?;
            }
            _ => {}
        }
        Ok(())
    }

    fn interested_in(&self) -> Vec<std::mem::Discriminant<DomainEvent>> {
        vec![
            std::mem::discriminant(&DomainEvent::UserCreated { user_id: UserId::new(), email: String::new() }),
            std::mem::discriminant(&DomainEvent::OrderPlaced {
                order_id: OrderId::new(),
                user_id: UserId::new(),
                amount: Decimal::ZERO
            }),
        ]
    }
}

// ✅ Event bus for managing observers
pub struct EventBus {
    sender: broadcast::Sender<DomainEvent>,
    handlers: Vec<Arc<dyn EventHandler + Send + Sync>>,
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1000);
        Self {
            sender,
            handlers: Vec::new(),
        }
    }

    pub fn subscribe(&mut self, handler: Arc<dyn EventHandler + Send + Sync>) {
        self.handlers.push(handler);
    }

    pub async fn publish(&self, event: DomainEvent) -> Result<(), EventError> {
        // Send to broadcast channel for other subscribers
        let _ = self.sender.send(event.clone());

        // Handle with registered handlers
        for handler in &self.handlers {
            let event_discriminant = std::mem::discriminant(&event);
            if handler.interested_in().contains(&event_discriminant) {
                if let Err(e) = handler.handle(&event).await {
                    tracing::error!("Event handler failed: {:?}", e);
                    // Continue with other handlers
                }
            }
        }

        Ok(())
    }

    pub fn subscribe_to_stream(&self) -> broadcast::Receiver<DomainEvent> {
        self.sender.subscribe()
    }
}
```

## 🏛️ STRUCTURAL PATTERNS

### Adapter Pattern for External APIs
```rust
// ✅ Adapter pattern for integrating different payment providers
#[async_trait::async_trait]
pub trait PaymentProcessor {
    async fn process_payment(&self, payment: &Payment) -> Result<PaymentResult, PaymentError>;
    async fn refund_payment(&self, payment_id: &str, amount: Option<Decimal>) -> Result<RefundResult, PaymentError>;
}

// External Stripe API (different interface)
pub struct StripeClient {
    // Stripe-specific implementation
}

impl StripeClient {
    pub async fn charge(&self, amount_cents: u64, token: &str) -> Result<StripeCharge, StripeError> {
        // Stripe-specific charge logic
    }

    pub async fn create_refund(&self, charge_id: &str, amount_cents: Option<u64>) -> Result<StripeRefund, StripeError> {
        // Stripe-specific refund logic
    }
}

// ✅ Adapter to make Stripe compatible with our interface
pub struct StripeAdapter {
    client: StripeClient,
}

impl StripeAdapter {
    pub fn new(client: StripeClient) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl PaymentProcessor for StripeAdapter {
    async fn process_payment(&self, payment: &Payment) -> Result<PaymentResult, PaymentError> {
        let amount_cents = (payment.amount * 100).to_u64().ok_or(PaymentError::InvalidAmount)?;

        let charge = self.client
            .charge(amount_cents, &payment.token)
            .await
            .map_err(|e| PaymentError::ProviderError(e.to_string()))?;

        Ok(PaymentResult {
            id: charge.id,
            status: match charge.status.as_str() {
                "succeeded" => PaymentStatus::Completed,
                "pending" => PaymentStatus::Pending,
                "failed" => PaymentStatus::Failed,
                _ => PaymentStatus::Unknown,
            },
            amount: payment.amount,
            fees: charge.fees.map(|f| Decimal::from(f) / 100),
        })
    }

    async fn refund_payment(&self, payment_id: &str, amount: Option<Decimal>) -> Result<RefundResult, PaymentError> {
        let amount_cents = amount.map(|a| (a * 100).to_u64().unwrap());

        let refund = self.client
            .create_refund(payment_id, amount_cents)
            .await
            .map_err(|e| PaymentError::ProviderError(e.to_string()))?;

        Ok(RefundResult {
            id: refund.id,
            amount: Decimal::from(refund.amount) / 100,
            status: RefundStatus::Completed,
        })
    }
}

// ✅ Similar adapter for PayPal
pub struct PayPalAdapter {
    client: PayPalClient,
}

#[async_trait::async_trait]
impl PaymentProcessor for PayPalAdapter {
    async fn process_payment(&self, payment: &Payment) -> Result<PaymentResult, PaymentError> {
        // PayPal-specific implementation
    }

    async fn refund_payment(&self, payment_id: &str, amount: Option<Decimal>) -> Result<RefundResult, PaymentError> {
        // PayPal-specific implementation
    }
}

// ✅ Payment service using any adapter
pub struct PaymentService {
    processor: Arc<dyn PaymentProcessor + Send + Sync>,
}

impl PaymentService {
    pub fn new(processor: Arc<dyn PaymentProcessor + Send + Sync>) -> Self {
        Self { processor }
    }

    pub async fn charge_customer(&self, payment: Payment) -> Result<PaymentResult, PaymentError> {
        self.processor.process_payment(&payment).await
    }
}
```

### Decorator Pattern with Middleware
```rust
// ✅ Decorator pattern for HTTP middleware
#[async_trait::async_trait]
pub trait HttpHandler {
    async fn handle(&self, request: Request) -> Result<Response, HttpError>;
}

// Base handler
pub struct BaseHandler;

#[async_trait::async_trait]
impl HttpHandler for BaseHandler {
    async fn handle(&self, request: Request) -> Result<Response, HttpError> {
        // Basic request handling
        Ok(Response::new("Hello World".into()))
    }
}

// ✅ Logging decorator
pub struct LoggingDecorator<H: HttpHandler> {
    inner: H,
}

impl<H: HttpHandler> LoggingDecorator<H> {
    pub fn new(inner: H) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<H: HttpHandler + Send + Sync> HttpHandler for LoggingDecorator<H> {
    async fn handle(&self, request: Request) -> Result<Response, HttpError> {
        let start = std::time::Instant::now();
        let method = request.method().clone();
        let uri = request.uri().clone();

        tracing::info!("Incoming request: {} {}", method, uri);

        let result = self.inner.handle(request).await;

        let duration = start.elapsed();
        match &result {
            Ok(response) => {
                tracing::info!(
                    "Request completed: {} {} -> {} in {:?}",
                    method, uri, response.status(), duration
                );
            }
            Err(e) => {
                tracing::error!(
                    "Request failed: {} {} -> {:?} in {:?}",
                    method, uri, e, duration
                );
            }
        }

        result
    }
}

// ✅ Rate limiting decorator
pub struct RateLimitDecorator<H: HttpHandler> {
    inner: H,
    rate_limiter: Arc<RateLimiter>,
}

impl<H: HttpHandler> RateLimitDecorator<H> {
    pub fn new(inner: H, rate_limiter: Arc<RateLimiter>) -> Self {
        Self { inner, rate_limiter }
    }
}

#[async_trait::async_trait]
impl<H: HttpHandler + Send + Sync> HttpHandler for RateLimitDecorator<H> {
    async fn handle(&self, request: Request) -> Result<Response, HttpError> {
        let client_ip = extract_client_ip(&request)?;

        self.rate_limiter.check_rate_limit(&client_ip).await
            .map_err(|_| HttpError::RateLimited)?;

        self.inner.handle(request).await
    }
}

// ✅ Composition of decorators
let handler = RateLimitDecorator::new(
    LoggingDecorator::new(
        BaseHandler
    ),
    rate_limiter
);
```

## 🧵 CONCURRENCY PATTERNS

### Actor Pattern with Tokio
```rust
use tokio::sync::{mpsc, oneshot};

// ✅ Actor pattern for managing state with message passing
#[derive(Debug)]
pub enum UserActorMessage {
    GetUser {
        user_id: UserId,
        respond_to: oneshot::Sender<Result<User, UserError>>,
    },
    UpdateUser {
        user_id: UserId,
        updates: UserUpdates,
        respond_to: oneshot::Sender<Result<User, UserError>>,
    },
    DeleteUser {
        user_id: UserId,
        respond_to: oneshot::Sender<Result<(), UserError>>,
    },
}

pub struct UserActor {
    receiver: mpsc::Receiver<UserActorMessage>,
    repository: Arc<dyn UserRepository + Send + Sync>,
    cache: DashMap<UserId, User>,
}

impl UserActor {
    pub fn new(repository: Arc<dyn UserRepository + Send + Sync>) -> (Self, UserActorHandle) {
        let (sender, receiver) = mpsc::channel(100);
        let actor = Self {
            receiver,
            repository,
            cache: DashMap::new(),
        };
        let handle = UserActorHandle { sender };
        (actor, handle)
    }

    pub async fn run(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
        }
    }

    async fn handle_message(&mut self, msg: UserActorMessage) {
        match msg {
            UserActorMessage::GetUser { user_id, respond_to } => {
                let result = self.get_user_internal(user_id).await;
                let _ = respond_to.send(result);
            }
            UserActorMessage::UpdateUser { user_id, updates, respond_to } => {
                let result = self.update_user_internal(user_id, updates).await;
                let _ = respond_to.send(result);
            }
            UserActorMessage::DeleteUser { user_id, respond_to } => {
                let result = self.delete_user_internal(user_id).await;
                let _ = respond_to.send(result);
            }
        }
    }

    async fn get_user_internal(&self, user_id: UserId) -> Result<User, UserError> {
        // Check cache first
        if let Some(user) = self.cache.get(&user_id) {
            return Ok(user.clone());
        }

        // Fetch from repository
        let user = self.repository.find_by_id(user_id).await?
            .ok_or(UserError::NotFound { user_id })?;

        // Cache the result
        self.cache.insert(user_id, user.clone());

        Ok(user)
    }

    async fn update_user_internal(&mut self, user_id: UserId, updates: UserUpdates) -> Result<User, UserError> {
        let updated_user = self.repository.update(user_id, updates).await?;

        // Update cache
        self.cache.insert(user_id, updated_user.clone());

        Ok(updated_user)
    }

    async fn delete_user_internal(&mut self, user_id: UserId) -> Result<(), UserError> {
        self.repository.delete(user_id).await?;

        // Remove from cache
        self.cache.remove(&user_id);

        Ok(())
    }
}

// ✅ Handle for communicating with the actor
#[derive(Clone)]
pub struct UserActorHandle {
    sender: mpsc::Sender<UserActorMessage>,
}

impl UserActorHandle {
    pub async fn get_user(&self, user_id: UserId) -> Result<User, UserError> {
        let (respond_to, response) = oneshot::channel();

        self.sender
            .send(UserActorMessage::GetUser { user_id, respond_to })
            .await
            .map_err(|_| UserError::ActorUnavailable)?;

        response.await
            .map_err(|_| UserError::ActorUnavailable)?
    }

    pub async fn update_user(&self, user_id: UserId, updates: UserUpdates) -> Result<User, UserError> {
        let (respond_to, response) = oneshot::channel();

        self.sender
            .send(UserActorMessage::UpdateUser { user_id, updates, respond_to })
            .await
            .map_err(|_| UserError::ActorUnavailable)?;

        response.await
            .map_err(|_| UserError::ActorUnavailable)?
    }
}

// ✅ Starting the actor system
pub async fn start_user_actor(repository: Arc<dyn UserRepository + Send + Sync>) -> UserActorHandle {
    let (actor, handle) = UserActor::new(repository);

    tokio::spawn(async move {
        actor.run().await;
    });

    handle
}
```

## ✅ DESIGN PATTERNS CHECKLIST

```markdown
### Design Patterns Implementation Verification
- [ ] Builder pattern used for complex configuration objects
- [ ] Factory pattern for creating related object families
- [ ] Strategy pattern for runtime algorithm selection
- [ ] Command pattern for operations requiring undo/redo
- [ ] Observer pattern for event-driven architecture
- [ ] Adapter pattern for external API integration
- [ ] Decorator pattern for cross-cutting concerns
- [ ] Actor pattern for concurrent state management
- [ ] Type-state pattern for compile-time validation
- [ ] Repository pattern for data access abstraction
- [ ] Dependency injection for testability
- [ ] Event sourcing for audit trails (when applicable)
- [ ] CQRS separation for read/write operations (when applicable)
- [ ] Circuit breaker for resilience patterns
- [ ] Retry pattern with exponential backoff
```

This design patterns guide provides battle-tested solutions for common architectural challenges in Rust applications.

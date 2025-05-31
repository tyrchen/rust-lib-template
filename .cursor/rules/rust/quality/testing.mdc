---
description:
globs:
alwaysApply: false
---
# 🧪 RUST TESTING STANDARDS

> **TL;DR:** Comprehensive testing guidelines for Rust projects covering unit tests, integration tests, property testing, benchmarks, and CI integration with best practices for test organization and coverage.

## 🔍 TESTING STRATEGY SELECTION

```mermaid
graph TD
    Start["Testing Requirements"] --> Strategy{"Testing Strategy?"}

    Strategy -->|"Unit Testing"| Unit["Unit Tests"]
    Strategy -->|"Integration Testing"| Integration["Integration Tests"]
    Strategy -->|"Property Testing"| Property["Property Testing"]
    Strategy -->|"Benchmarking"| Benchmark["Performance Benchmarks"]
    Strategy -->|"End-to-End Testing"| E2E["E2E Tests"]

    Unit --> UnitFeatures["Unit Test Features:"]
    Integration --> IntegrationFeatures["Integration Features:"]
    Property --> PropertyFeatures["Property Features:"]
    Benchmark --> BenchmarkFeatures["Benchmark Features:"]
    E2E --> E2EFeatures["E2E Features:"]

    UnitFeatures --> UnitItems["• Individual function testing<br>• Mock dependencies<br>• Fast execution<br>• High coverage"]
    IntegrationFeatures --> IntegrationItems["• Multi-module testing<br>• Real dependencies<br>• Realistic scenarios<br>• API testing"]
    PropertyFeatures --> PropertyItems["• Random input testing<br>• Edge case discovery<br>• Invariant verification<br>• Fuzzing"]
    BenchmarkFeatures --> BenchmarkItems["• Performance regression<br>• Memory usage tracking<br>• Throughput measurement<br>• Optimization validation"]
    E2EFeatures --> E2EItems["• Full system testing<br>• User workflow validation<br>• External service mocking<br>• Production-like environment"]

    UnitItems --> Tools["Testing Tools"]
    IntegrationItems --> Tools
    PropertyItems --> Tools
    BenchmarkItems --> Tools
    E2EItems --> Tools

    Tools --> MockTool["Mocking: mockall"]
    Tools --> PropertyTool["Property: proptest"]
    Tools --> BenchTool["Benchmarks: criterion"]
    Tools --> WebTool["Web Testing: axum-test"]
    Tools --> HttpTool["HTTP Mocking: wiremock"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style Strategy fill:#ffa64d,stroke:#cc7a30,color:white
    style Unit fill:#4dbb5f,stroke:#36873f,color:white
    style Integration fill:#d94dbb,stroke:#a3378a,color:white
    style Property fill:#9f4dbb,stroke:#7a3787,color:white
    style Benchmark fill:#bb4d4d,stroke:#873636,color:white
    style E2E fill:#bbbb4d,stroke:#878736,color:white
```

## 🏗️ CARGO TEST ORGANIZATION

### Project Structure for Testing

```rust
// Project structure with comprehensive testing
my_project/
├── Cargo.toml
├── src/
│   ├── lib.rs           // Library root with unit tests
│   ├── main.rs          // Binary entry point
│   ├── user/
│   │   ├── mod.rs       // Module with inline unit tests
│   │   ├── service.rs   // Service with unit tests
│   │   └── repository.rs // Repository with unit tests
│   └── product/
│       ├── mod.rs
│       └── catalog.rs
├── tests/               // Integration tests directory
│   ├── integration_test.rs
│   ├── api_test.rs
│   └── common/          // Shared test utilities
│       └── mod.rs
└── benches/             // Benchmark tests
    ├── user_benchmarks.rs
    └── product_benchmarks.rs
```

### Unit Test Configuration

```rust
// src/user/service.rs
use crate::user::{User, UserRepository, UserError};
use mockall::predicate::*;

pub struct UserService<R: UserRepository> {
    repository: R,
}

impl<R: UserRepository> UserService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn create_user(&self, user: User) -> Result<User, UserError> {
        // Validate user data
        if user.email.is_empty() {
            return Err(UserError::InvalidInput("Email cannot be empty".to_string()));
        }

        // Save to repository
        self.repository.save(user).await
    }

    pub async fn find_user(&self, id: &str) -> Result<Option<User>, UserError> {
        if id.is_empty() {
            return Err(UserError::InvalidInput("ID cannot be empty".to_string()));
        }

        self.repository.find_by_id(id).await
    }
}

// ✅ Unit tests in the same file
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;

    // Mock the repository trait
    mock! {
        TestUserRepository {}

        #[async_trait::async_trait]
        impl UserRepository for TestUserRepository {
            async fn save(&self, user: User) -> Result<User, UserError>;
            async fn find_by_id(&self, id: &str) -> Result<Option<User>, UserError>;
        }
    }

    #[tokio::test]
    async fn test_create_user_success() {
        let mut mock_repo = MockTestUserRepository::new();
        let user = User {
            id: "123".to_string(),
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
        };

        mock_repo
            .expect_save()
            .with(eq(user.clone()))
            .times(1)
            .returning(|user| Ok(user));

        let service = UserService::new(mock_repo);
        let result = service.create_user(user.clone()).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), user);
    }

    #[tokio::test]
    async fn test_create_user_empty_email_fails() {
        let mock_repo = MockTestUserRepository::new();
        let user = User {
            id: "123".to_string(),
            email: "".to_string(),  // Empty email
            name: "Test User".to_string(),
        };

        let service = UserService::new(mock_repo);
        let result = service.create_user(user).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), UserError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn test_find_user_success() {
        let mut mock_repo = MockTestUserRepository::new();
        let expected_user = User {
            id: "123".to_string(),
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
        };

        mock_repo
            .expect_find_by_id()
            .with(eq("123"))
            .times(1)
            .returning(move |_| Ok(Some(expected_user.clone())));

        let service = UserService::new(mock_repo);
        let result = service.find_user("123").await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_find_user_empty_id_fails() {
        let mock_repo = MockTestUserRepository::new();
        let service = UserService::new(mock_repo);

        let result = service.find_user("").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), UserError::InvalidInput(_)));
    }
}
```

## 🔗 INTEGRATION TESTING

### Integration Test Structure

```rust
// tests/integration_test.rs
use my_project::{User, UserService, PostgresUserRepository};
use testcontainers::{clients::Cli, images::postgres::Postgres, Container};
use sqlx::PgPool;

struct TestContext {
    pool: PgPool,
    _container: Container<'static, Postgres>,
}

impl TestContext {
    async fn new() -> Self {
        let docker = Cli::default();
        let container = docker.run(Postgres::default());
        let host_port = container.get_host_port_ipv4(5432);

        let database_url = format!("postgres://postgres:password@localhost:{}/test", host_port);
        let pool = PgPool::connect(&database_url).await.unwrap();

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        Self {
            pool,
            _container: container,
        }
    }
}

#[tokio::test]
async fn test_user_service_integration() {
    let ctx = TestContext::new().await;
    let repository = PostgresUserRepository::new(ctx.pool.clone());
    let service = UserService::new(repository);

    let user = User {
        id: "integration-test-123".to_string(),
        email: "integration@example.com".to_string(),
        name: "Integration User".to_string(),
    };

    // Test create
    let created_user = service.create_user(user.clone()).await.unwrap();
    assert_eq!(created_user.email, user.email);

    // Test find
    let found_user = service.find_user(&user.id).await.unwrap();
    assert!(found_user.is_some());
    assert_eq!(found_user.unwrap().id, user.id);
}

#[tokio::test]
async fn test_duplicate_user_creation_fails() {
    let ctx = TestContext::new().await;
    let repository = PostgresUserRepository::new(ctx.pool.clone());
    let service = UserService::new(repository);

    let user = User {
        id: "duplicate-test-123".to_string(),
        email: "duplicate@example.com".to_string(),
        name: "Duplicate User".to_string(),
    };

    // First creation should succeed
    service.create_user(user.clone()).await.unwrap();

    // Second creation should fail
    let result = service.create_user(user).await;
    assert!(result.is_err());
}
```

## 🧬 PROPERTY TESTING WITH PROPTEST

### Property Test Configuration

```rust
// Cargo.toml
[dev-dependencies]
proptest = "1.5"

// src/user/validation.rs
use proptest::prelude::*;

pub fn validate_email(email: &str) -> bool {
    email.contains('@') && email.len() > 3 && email.len() < 255
}

pub fn validate_username(username: &str) -> bool {
    username.len() >= 3 && username.len() <= 50 && username.chars().all(|c| c.is_alphanumeric() || c == '_')
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_valid_email_always_contains_at(email in r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
            prop_assert!(validate_email(&email));
        }

        #[test]
        fn test_invalid_email_without_at(email in r"[a-zA-Z0-9._%+-]+[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
            prop_assert!(!validate_email(&email));
        }

        #[test]
        fn test_username_length_bounds(username in r"[a-zA-Z0-9_]{3,50}") {
            prop_assert!(validate_username(&username));
        }

        #[test]
        fn test_username_too_short(username in r"[a-zA-Z0-9_]{1,2}") {
            prop_assert!(!validate_username(&username));
        }

        #[test]
        fn test_username_too_long(username in r"[a-zA-Z0-9_]{51,100}") {
            prop_assert!(!validate_username(&username));
        }

        #[test]
        fn test_username_invalid_chars(username in r"[a-zA-Z0-9_]*[^a-zA-Z0-9_]+[a-zA-Z0-9_]*") {
            prop_assume!(!username.is_empty());
            prop_assert!(!validate_username(&username));
        }
    }

    // Custom strategy for generating valid users
    fn valid_user_strategy() -> impl Strategy<Value = User> {
        (
            r"user[0-9]{1,6}",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            r"[A-Z][a-z]{2,20} [A-Z][a-z]{2,20}",
        )
            .prop_map(|(id, email, name)| User { id, email, name })
    }

    proptest! {
        #[test]
        fn test_user_serialization_roundtrip(user in valid_user_strategy()) {
            let json = serde_json::to_string(&user).unwrap();
            let deserialized: User = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(user, deserialized);
        }
    }
}
```

## 🚀 PERFORMANCE BENCHMARKING

### Criterion Benchmark Setup

```rust
// Cargo.toml
[[bench]]
name = "user_benchmarks"
harness = false

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

// benches/user_benchmarks.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use my_project::{User, UserService, InMemoryUserRepository};

fn create_user_benchmark(c: &mut Criterion) {
    let repository = InMemoryUserRepository::new();
    let service = UserService::new(repository);

    c.bench_function("create_user", |b| {
        b.iter(|| {
            let user = User {
                id: format!("bench-{}", fastrand::u64(..)),
                email: "bench@example.com".to_string(),
                name: "Benchmark User".to_string(),
            };

            black_box(service.create_user(user))
        })
    });
}

fn find_user_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_user");

    for size in [100, 1000, 10000].iter() {
        let repository = InMemoryUserRepository::new();
        let service = UserService::new(repository);

        // Pre-populate with users
        for i in 0..*size {
            let user = User {
                id: format!("user-{}", i),
                email: format!("user{}@example.com", i),
                name: format!("User {}", i),
            };
            service.create_user(user).unwrap();
        }

        group.bench_with_input(BenchmarkId::new("size", size), size, |b, &size| {
            b.iter(|| {
                let user_id = format!("user-{}", fastrand::usize(0..size));
                black_box(service.find_user(&user_id))
            })
        });
    }
    group.finish();
}

criterion_group!(benches, create_user_benchmark, find_user_benchmark);
criterion_main!(benches);
```

## 🌐 WEB API TESTING

### Axum Test Integration

```rust
// Cargo.toml
[dev-dependencies]
axum-test = "16"
wiremock = "0.6"

// tests/api_test.rs
use axum_test::TestServer;
use my_project::{create_app, AppState};
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

#[tokio::test]
async fn test_create_user_api() {
    let app_state = AppState::new_test();
    let app = create_app(app_state);
    let server = TestServer::new(app).unwrap();

    let user_data = serde_json::json!({
        "email": "api@example.com",
        "name": "API User"
    });

    let response = server
        .post("/users")
        .json(&user_data)
        .await;

    response.assert_status_created();
    response.assert_json(&serde_json::json!({
        "id": response.json::<serde_json::Value>()["id"],
        "email": "api@example.com",
        "name": "API User"
    }));
}

#[tokio::test]
async fn test_external_service_integration() {
    // Mock external service
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/external/users/123"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_json(&serde_json::json!({
                "id": "123",
                "verified": true
            })))
        .mount(&mock_server)
        .await;

    let app_state = AppState::new_test_with_external_url(&mock_server.uri());
    let app = create_app(app_state);
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/users/123/verification")
        .await;

    response.assert_status_ok();
    response.assert_json(&serde_json::json!({
        "verified": true
    }));
}
```

## 📊 COVERAGE AND CI INTEGRATION

### Coverage Configuration

```bash
# Install tarpaulin for coverage
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out html --output-dir coverage

# CI-friendly coverage
cargo tarpaulin --out xml --output-dir coverage
```

### GitHub Actions Configuration

```yaml
# .github/workflows/test.yml
name: Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: password
          POSTGRES_DB: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - uses: actions/checkout@v4

    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
      with:
        components: rustfmt, clippy

    - name: Cache dependencies
      uses: actions/cache@v4
      with:
        path: |
          ~/.cargo/bin/
          ~/.cargo/registry/index/
          ~/.cargo/registry/cache/
          ~/.cargo/git/db/
          target/
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

    - name: Check formatting
      run: cargo fmt --all -- --check

    - name: Clippy
      run: cargo clippy --all-targets --all-features -- -D warnings

    - name: Unit Tests
      run: cargo test --lib
      env:
        DATABASE_URL: postgres://postgres:password@localhost:5432/test

    - name: Integration Tests
      run: cargo test --test '*'
      env:
        DATABASE_URL: postgres://postgres:password@localhost:5432/test

    - name: Doc Tests
      run: cargo test --doc

    - name: Benchmarks (check only)
      run: cargo bench --no-run

  coverage:
    runs-on: ubuntu-latest
    needs: test

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: password
          POSTGRES_DB: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - uses: actions/checkout@v4

    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable

    - name: Install tarpaulin
      run: cargo install cargo-tarpaulin

    - name: Generate coverage
      run: cargo tarpaulin --out xml --output-dir coverage
      env:
        DATABASE_URL: postgres://postgres:password@localhost:5432/test

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v4
      with:
        file: coverage/cobertura.xml
        fail_ci_if_error: true
```

## ✅ TESTING CHECKLIST

```markdown
### Testing Completeness Verification
- [ ] Unit tests for all public functions
- [ ] Unit tests use mocking for external dependencies
- [ ] Integration tests cover realistic scenarios
- [ ] Property tests validate invariants
- [ ] Benchmarks track performance regressions
- [ ] Test coverage > 80% for core modules
- [ ] Tests run in CI/CD pipeline
- [ ] No `unwrap()` or `expect()` in test code
- [ ] Test data is deterministic or properly seeded
- [ ] Async tests use `#[tokio::test]`
- [ ] Web API tests cover error cases
- [ ] External services are properly mocked
- [ ] Database tests use transactions or containers
- [ ] Tests are organized by functionality
- [ ] Test names clearly describe scenarios
```

## 📚 TESTING DEPENDENCIES

### Essential Testing Crates

```toml
[dev-dependencies]
# Core testing
tokio-test = "0.4"          # Async testing utilities

# Mocking
mockall = "0.13"            # Mock generation
wiremock = "0.6"           # HTTP service mocking

# Property testing
proptest = "1.5"           # Property-based testing

# Benchmarking
criterion = { version = "0.5", features = ["html_reports"] }

# Web testing
axum-test = "16"           # Axum application testing

# Database testing
testcontainers = "0.21"    # Docker containers for tests
sqlx = { version = "0.8", features = ["testing"] }

# Utilities
tempfile = "3.13"          # Temporary files for tests
serde_json = "1.0"         # JSON serialization for tests
```

This comprehensive testing standard ensures robust, reliable Rust applications with thorough test coverage and quality assurance.

---
description:
globs:
alwaysApply: false
---
# 🗄️ RUST DATABASE BEST PRACTICES

> **TL;DR:** Comprehensive guidelines for database access in Rust using SQLx, focusing on type safety, async patterns, and testing strategies.

## 🔍 DATABASE ARCHITECTURE STRATEGY

```mermaid
graph TD
    Start["Database Integration"] --> DBChoice{"Database<br>Type?"}

    DBChoice -->|PostgreSQL| Postgres["PostgreSQL with SQLx"]
    DBChoice -->|SQLite| SQLite["SQLite with SQLx"]
    DBChoice -->|Multiple| MultiDB["Multi-Database Support"]

    Postgres --> ConnectionPool["Connection Pool Setup"]
    SQLite --> ConnectionPool
    MultiDB --> ConnectionPool

    ConnectionPool --> Migrations["Database Migrations"]
    Migrations --> EntityDesign["Entity Design"]

    EntityDesign --> RepositoryPattern["Repository Pattern"]
    RepositoryPattern --> QueryPatterns["Query Patterns"]

    QueryPatterns --> TypeSafety["Type Safety"]
    TypeSafety --> ErrorHandling["Error Handling"]

    ErrorHandling --> Testing["Database Testing"]
    Testing --> Transactions["Transaction Management"]
    Transactions --> Performance["Performance Optimization"]

    Performance --> Production["Production Database"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style ConnectionPool fill:#4dbb5f,stroke:#36873f,color:white
    style RepositoryPattern fill:#ffa64d,stroke:#cc7a30,color:white
    style Testing fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 DATABASE LIBRARY SELECTION

### SQLx as the Standard
- **Always use SQLx** - avoid `rusqlite`, `tokio-postgres`, or other lower-level libraries
- **Support multiple databases** through SQLx's unified interface
- **Leverage compile-time query checking** when possible
- **Use async/await patterns** for all database operations

```toml
# Cargo.toml - SQLx configuration
[dependencies]
sqlx = { version = "0.8", features = [
    "chrono",
    "postgres",
    "runtime-tokio-rustls",
    "sqlite",
    "uuid"
] }
```

## 🔧 QUERY PATTERNS

### Use sqlx::query_as Instead of Macros
```rust
// ✅ Preferred: Use sqlx::query_as with custom types
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

impl User {
    pub async fn find_by_id(
        pool: &PgPool,
        id: Uuid
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT id, username, email, created_at, updated_at, is_active
             FROM users
             WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    pub async fn list_active_users(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT id, username, email, created_at, updated_at, is_active
             FROM users
             WHERE is_active = true
             ORDER BY created_at DESC
             LIMIT $1 OFFSET $2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }
}

// ❌ Avoid: sqlx::query! macro (compile-time dependencies)
// let result = sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)
//     .fetch_one(pool)
//     .await?;
```

### Entity Definition Patterns
```rust
use sqlx::{FromRow, PgPool, Row};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Product {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub price: rust_decimal::Decimal,
    pub category_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_available: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProductRequest {
    pub name: String,
    pub description: Option<String>,
    pub price: rust_decimal::Decimal,
    pub category_id: Uuid,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProductRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price: Option<rust_decimal::Decimal>,
    pub is_available: Option<bool>,
}
```

## 🏗️ REPOSITORY PATTERN

### Repository Implementation
```rust
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

#[async_trait]
pub trait UserRepository {
    async fn create(&self, request: CreateUserRequest) -> Result<User, sqlx::Error>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, sqlx::Error>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error>;
    async fn update(&self, id: Uuid, request: UpdateUserRequest) -> Result<Option<User>, sqlx::Error>;
    async fn delete(&self, id: Uuid) -> Result<bool, sqlx::Error>;
    async fn list(&self, limit: i64, offset: i64) -> Result<Vec<User>, sqlx::Error>;
}

pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create(&self, request: CreateUserRequest) -> Result<User, sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query_as::<_, User>(
            "INSERT INTO users (id, username, email, created_at, updated_at, is_active)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, username, email, created_at, updated_at, is_active"
        )
        .bind(id)
        .bind(&request.username)
        .bind(&request.email)
        .bind(now)
        .bind(now)
        .bind(true)
        .fetch_one(&self.pool)
        .await
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT id, username, email, created_at, updated_at, is_active
             FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT id, username, email, created_at, updated_at, is_active
             FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
    }

    async fn update(&self, id: Uuid, request: UpdateUserRequest) -> Result<Option<User>, sqlx::Error> {
        let now = Utc::now();

        sqlx::query_as::<_, User>(
            "UPDATE users
             SET username = COALESCE($2, username),
                 email = COALESCE($3, email),
                 is_active = COALESCE($4, is_active),
                 updated_at = $5
             WHERE id = $1
             RETURNING id, username, email, created_at, updated_at, is_active"
        )
        .bind(id)
        .bind(request.username)
        .bind(request.email)
        .bind(request.is_active)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
    }

    async fn delete(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn list(&self, limit: i64, offset: i64) -> Result<Vec<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            "SELECT id, username, email, created_at, updated_at, is_active
             FROM users
             ORDER BY created_at DESC
             LIMIT $1 OFFSET $2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
    }
}
```

## 🧪 DATABASE TESTING

### Using sqlx-db-tester for Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sqlx_db_tester::TestPg;

    async fn setup_test_db() -> PgPool {
        let tester = TestPg::new(
            "postgres://postgres:password@localhost/test".to_string(),
            std::path::Path::new("./migrations"),
        );
        let pool = tester.get_pool().await;

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        pool
    }

    #[tokio::test]
    async fn test_create_user() {
        let pool = setup_test_db().await;
        let repo = PostgresUserRepository::new(pool);

        let request = CreateUserRequest {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
        };

        let user = repo.create(request).await.unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert!(user.is_active);
    }

    #[tokio::test]
    async fn test_find_user_by_email() {
        let pool = setup_test_db().await;
        let repo = PostgresUserRepository::new(pool);

        // Create a user first
        let create_request = CreateUserRequest {
            username: "findme".to_string(),
            email: "findme@example.com".to_string(),
        };
        let created_user = repo.create(create_request).await.unwrap();

        // Find by email
        let found_user = repo.find_by_email("findme@example.com").await.unwrap();
        assert!(found_user.is_some());
        assert_eq!(found_user.unwrap().id, created_user.id);
    }

    #[tokio::test]
    async fn test_update_user() {
        let pool = setup_test_db().await;
        let repo = PostgresUserRepository::new(pool);

        // Create a user
        let create_request = CreateUserRequest {
            username: "updateme".to_string(),
            email: "updateme@example.com".to_string(),
        };
        let user = repo.create(create_request).await.unwrap();

        // Update the user
        let update_request = UpdateUserRequest {
            username: Some("updated_name".to_string()),
            email: None,
            is_active: Some(false),
        };

        let updated_user = repo.update(user.id, update_request).await.unwrap();
        assert!(updated_user.is_some());
        let updated_user = updated_user.unwrap();
        assert_eq!(updated_user.username, "updated_name");
        assert!(!updated_user.is_active);
    }
}
```

## 📋 MIGRATION PATTERNS

### Migration File Structure
```sql
-- migrations/20240501000001_create_users_table.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Add trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

### Product Table Example
```sql
-- migrations/20240501000002_create_products_table.sql
CREATE TABLE categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    category_id UUID NOT NULL REFERENCES categories(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_available BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX idx_products_category ON products(category_id);
CREATE INDEX idx_products_price ON products(price);
CREATE INDEX idx_products_name ON products(name);

CREATE TRIGGER update_products_updated_at
    BEFORE UPDATE ON products
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

## 🔧 CONNECTION MANAGEMENT

### Database Pool Configuration
```rust
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

pub async fn create_connection_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .min_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect(database_url)
        .await
}

// Application setup
pub async fn setup_database(config: &DatabaseConfig) -> Result<PgPool, Box<dyn std::error::Error>> {
    let pool = create_connection_pool(&config.url).await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}
```

## 🚨 ANTI-PATTERNS TO AVOID

### Database Anti-Patterns
```rust
// ❌ Don't use rusqlite or tokio-postgres directly
// use rusqlite::{Connection, Result};
// use tokio_postgres::{NoTls, connect};

// ❌ Don't use sqlx::query! macro in production
// let user = sqlx::query!("SELECT * FROM users WHERE id = $1", id)
//     .fetch_one(pool)
//     .await?;

// ❌ Don't create entities without FromRow
// struct User {
//     id: Uuid,
//     name: String,
// }
// // Missing: #[derive(FromRow)]

// ❌ Don't forget serde camelCase configuration
// #[derive(Serialize, Deserialize)]
// struct User {  // Missing: #[serde(rename_all = "camelCase")]
//     user_id: String,
// }

// ❌ Don't create repositories without async traits
// impl UserRepository {
//     fn find_by_id(&self, id: Uuid) -> User {  // Should be async
//         // ...
//     }
// }
```

## ✅ DATABASE CHECKLIST

```markdown
### Database Implementation Verification
- [ ] Uses SQLx (not rusqlite/tokio-postgres)
- [ ] Entities derive `FromRow`, `Serialize`, `Deserialize`
- [ ] All serde structs use `#[serde(rename_all = "camelCase")]`
- [ ] Uses `sqlx::query_as` instead of `sqlx::query!` macro
- [ ] Repository pattern with async traits
- [ ] Comprehensive unit tests with sqlx-db-tester
- [ ] Migration files in `migrations/` directory
- [ ] Connection pool properly configured
- [ ] Proper error handling (no unwrap/expect)
- [ ] All database operations are async
- [ ] Tests cover CRUD operations
- [ ] Indexes defined for query performance
```

This database standard ensures type-safe, performant, and testable database access patterns across Rust applications.

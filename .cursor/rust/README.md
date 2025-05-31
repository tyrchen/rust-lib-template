# 🦀 Rust Large System Development Rules

> **A comprehensive rule system for building production-ready, scalable Rust applications with consistent architecture patterns, proper error handling, and modern concurrency patterns.**

## 📚 Rule System Overview

This rule system automatically selects appropriate architectural patterns, dependency management strategies, and coding standards based on project complexity and functional requirements. It ensures maintainability and scalability of large Rust systems through:

- **Complexity-driven architecture decisions**
- **Proper error handling patterns** (thiserror for libs, anyhow for bins)
- **Frontend-friendly serialization** (CamelCase JSON output)
- **Type-safe builder patterns** for complex constructors
- **Lock-free concurrency patterns** using modern primitives
- **Structured dependency management** with workspaces

## 🏗️ Rule Architecture

```
.cursor/rust/
├── core/                           # Core rule system
│   ├── main.mdc                   # Main rule entry point
│   ├── complexity-detection.mdc   # Project complexity analysis
│   └── workspace-management.mdc   # Workspace organization
├── modules/                        # Feature-specific rules
│   ├── error-handling/            # Error handling patterns
│   │   ├── lib-error-patterns.mdc # thiserror for libraries
│   │   └── bin-error-patterns.mdc # anyhow for binaries
│   ├── serde-config/              # Serialization rules
│   │   └── camelcase-patterns.mdc # CamelCase JSON output
│   ├── builder-patterns/          # Constructor patterns
│   │   └── typed-builder.mdc      # TypedBuilder for ≥4 params
│   ├── concurrency/               # Concurrency patterns
│   │   └── lock-free-patterns.mdc # DashMap, atomics, ArcSwap
│   └── [other modules...]         # Additional patterns
└── workflows/                      # Development workflows
    └── development-workflow.mdc    # Complete dev lifecycle
```

## 🎯 Quick Start

### 1. Project Initialization

The rule system automatically detects project complexity:

- **Simple (0-6 points)**: Single crate, basic patterns
- **Medium (7-15 points)**: Multi-module, structured errors, builders
- **Complex (16+ points)**: Workspace, advanced patterns, full concurrency

### 2. Automatic Rule Loading

Rules are automatically loaded based on:
- Project complexity score
- Detected dependencies (axum, sqlx, etc.)
- Crate types (lib vs bin)
- Feature requirements

### 3. Example Project Structure

For a complex web application:

```
my-app/
├── Cargo.toml              # Workspace configuration
├── apps/                   # Binary crates (use anyhow)
│   ├── api-server/
│   └── cli-tool/
├── libs/                   # Library crates (use thiserror)
│   ├── core/
│   ├── database/
│   └── shared-types/
└── tools/                  # Development tools
    └── migration-tool/
```

## 📋 Rule Categories

### 🏗️ Core Architecture Rules

**Workspace Management** (`core/workspace-management.mdc`)
- Multi-crate projects use workspace organization
- Centralized dependency management in `[workspace.dependencies]`
- Consistent version management across crates

**Complexity Detection** (`core/complexity-detection.mdc`)
- Automated project complexity assessment
- Rule selection based on complexity score
- Adaptive architectural recommendations

### 🚨 Error Handling Rules

**Library Error Patterns** (`modules/error-handling/lib-error-patterns.mdc`)
- Use `thiserror` for structured error types
- Box large errors to avoid Result bloat
- Domain-specific error hierarchies

**Binary Error Patterns** (`modules/error-handling/bin-error-patterns.mdc`)
- Use `anyhow` for pragmatic error handling
- Rich error context with `.context()`
- User-friendly error reporting

### 📦 Serialization Rules

**CamelCase Patterns** (`modules/serde-config/camelcase-patterns.mdc`)
- All structs must use `#[serde(rename_all = "camelCase")]`
- Consistent JSON output for frontend consumption
- Proper handling of nested structures

### 🏗️ Constructor Rules

**TypedBuilder Patterns** (`modules/builder-patterns/typed-builder.mdc`)
- Use TypedBuilder for structs with ≥4 parameters
- Proper default values and optional field handling
- Type-safe construction with compile-time validation

### 🏗️ Domain Organization Rules

**Domain-Driven Structure** (`modules/domain-organization/domain-driven-structure.mdc`)
- Organize by business domain, not technical layers
- Use meaningful file names (node.rs, workflow.rs, execution.rs)
- Avoid generic names (models.rs, types.rs, traits.rs)

### 🗄️ Database Rules

**SQLx Patterns** (`modules/database/sqlx-patterns.mdc`)
- Use `sqlx::query_as` with `FromRow` derive for type safety
- NEVER use `sqlx::query!` macro
- Repository pattern with proper error handling

### 🧪 Testing Rules

**Unit Test Patterns** (`modules/testing/unit-test-patterns.mdc`)
- Unit tests MUST be in same file as implementation
- Use `sqlx-db-tester` for database tests
- Comprehensive coverage with in-file organization

### ⚡ Concurrency Rules

**Lock-free Patterns** (`modules/concurrency/lock-free-patterns.mdc`)
- Use `DashMap` instead of `Mutex<HashMap<_, _>>`
- Real-world node registry patterns
- Atomic types for simple counters and flags

## 🔧 Implementation Examples

### Error Handling

```rust
// Library crate (libs/core/src/lib.rs)
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Invalid configuration: {message}")]
    InvalidConfig { message: String },

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

// Binary crate (apps/api-server/src/main.rs)
use anyhow::{Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    run_server()
        .await
        .context("Server startup failed")?;
    Ok(())
}
```

### Serialization

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub user_id: String,
    pub first_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// Outputs: {"userId": "123", "firstName": "John", "createdAt": "2023-..."}
```

### Builder Patterns

```rust
use typed_builder::TypedBuilder;

#[derive(TypedBuilder)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,

    #[builder(default = 10)]
    pub max_connections: u32,

    #[builder(default, setter(strip_option))]
    pub password: Option<String>,
}

// Usage:
let config = DatabaseConfig::builder()
    .host("localhost")
    .port(5432)
    .password("secret")
    .build();
```

### Domain Organization

```rust
// ❌ AVOID: Technical layer organization
// src/models.rs, src/types.rs, src/traits.rs

// ✅ REQUIRED: Domain-driven organization
// crates/common/src/node.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]  // MANDATORY
pub struct NodeExecutionData {
    pub json: serde_json::Value,
    pub binary: Option<BinaryData>,
}

// crates/common/src/workflow.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]  // MANDATORY
pub struct Workflow {
    pub id: WorkflowId,
    pub name: String,
    pub active: bool,
}
```

### Database Patterns

```rust
// crates/storage/src/repositories/workflow.rs
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]  // MANDATORY
pub struct WorkflowEntity {
    pub id: Uuid,
    pub name: String,
    pub active: bool,
    pub workflow_data: serde_json::Value,
}

impl WorkflowRepository {
    // ✅ ALWAYS use query_as, NEVER query! macro
    pub async fn create(&self, workflow: &WorkflowEntity) -> StorageResult<WorkflowEntity> {
        let created = sqlx::query_as::<_, WorkflowEntity>(
            "INSERT INTO workflows (id, name, active, workflow_data) VALUES ($1, $2, $3, $4) RETURNING *"
        )
        .bind(workflow.id)
        .bind(&workflow.name)
        .bind(workflow.active)
        .bind(&workflow.workflow_data)
        .fetch_one(&self.pool)
        .await?;

        Ok(created)
    }
}
```

### Testing Patterns

```rust
// crates/common/src/node.rs - Tests in same file
pub struct NodeExecutionData {
    pub json: serde_json::Value,
}

// ✅ TESTS IN SAME FILE - MANDATORY
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_node_execution_data_serialization() {
        let data = NodeExecutionData {
            json: json!({"testKey": "value"}),
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert!(serialized.contains("\"json\""));  // camelCase verified
    }

    #[tokio::test]
    async fn test_database_repository() {
        use sqlx_db_tester::TestPg;

        let tdb = TestPg::new("postgres://...", std::path::Path::new("./migrations"));
        tdb.setup().await;
        let pool = tdb.get_pool().await;

        // Test with real database...
    }
}
```

### Concurrency

```rust
// crates/engine/src/registry.rs - Real-world node registry
use dashmap::DashMap;
use std::sync::Arc;

pub struct NodeRegistry {
    nodes: DashMap<String, Arc<dyn NodeType>>,
    metadata: DashMap<String, NodeTypeMetadata>,
}

impl NodeRegistry {
    pub fn register_node<T>(&self, node: T) -> Result<(), NodeError>
    where
        T: NodeType + 'static,
    {
        let node_type = node.get_node_type().to_string();

        // Atomic insertions - no locks needed
        self.nodes.insert(node_type.clone(), Arc::new(node));

        Ok(())
    }

    pub fn get_node(&self, node_type: &str) -> Option<Arc<dyn NodeType>> {
        self.nodes.get(node_type).map(|entry| entry.value().clone())
    }
}
```

## 🚨 Rule Enforcement

### Validation Checklist

```bash
# Run quality checks
cargo build --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# Check rule compliance
./scripts/check_rule_compliance.sh
```

### CI/CD Integration

The rule system includes GitHub Actions workflows for automated validation:

- **Build verification**: All crates compile successfully
- **Test execution**: All tests pass
- **Code quality**: Clippy and formatting checks
- **Rule compliance**: Automated pattern validation

## 📖 Rule Reference

| Rule File | Purpose | When Applied |
|-----------|---------|--------------|
| `core/main.mdc` | Main rule coordinator | Always |
| `core/complexity-detection.mdc` | Project analysis | Project initialization |
| `core/workspace-management.mdc` | Multi-crate organization | Complex projects |
| `modules/domain-organization/domain-driven-structure.mdc` | Domain-driven organization | All projects |
| `modules/error-handling/lib-error-patterns.mdc` | Library error handling | Library crates |
| `modules/error-handling/bin-error-patterns.mdc` | Binary error handling | Binary crates |
| `modules/serde-config/camelcase-patterns.mdc` | JSON serialization | Serde usage |
| `modules/builder-patterns/typed-builder.mdc` | Complex constructors | ≥4 parameters |
| `modules/database/sqlx-patterns.mdc` | Database patterns | SQLx usage |
| `modules/testing/unit-test-patterns.mdc` | Testing patterns | All code |
| `modules/concurrency/lock-free-patterns.mdc` | High-performance concurrency | Concurrent operations |
| `workflows/development-workflow.mdc` | Complete development process | Always |

## 🎯 Benefits

### 🔄 Consistency
- Uniform error handling patterns across all crates
- Consistent JSON output format for APIs
- Standardized dependency management

### 📈 Scalability
- Workspace organization for large projects
- Lock-free concurrency for high performance
- Modular architecture with clear boundaries

### 🛡️ Reliability
- Type-safe construction patterns
- Comprehensive error handling
- Automated quality enforcement

### 👥 Developer Experience
- Clear architectural guidelines
- Automated rule selection
- Comprehensive documentation and examples

## 🚀 Getting Started

1. **Clone/copy the rules** into your project's `.cursor/rust/` directory
2. **Initialize your project** following the complexity assessment
3. **Apply the appropriate patterns** based on your project type
4. **Run quality checks** to ensure compliance
5. **Integrate CI/CD** for continuous validation

The rule system will guide you through building robust, maintainable Rust applications that follow best practices and scale effectively.

---

> **Note**: This rule system is designed to work with modern Rust (1.70+) and integrates seamlessly with popular ecosystem crates like tokio, axum, sqlx, and serde.

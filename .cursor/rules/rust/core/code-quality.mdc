---
description:
globs:
alwaysApply: false
---
# 🦀 RUST CORE CODE QUALITY STANDARDS

> **TL;DR:** Essential code quality rules for all Rust projects, focusing on maintainable, production-ready code that follows modern Rust 2024 idioms.

## 🔍 CODE QUALITY STRATEGY SELECTION

```mermaid
graph TD
    Start["Code Quality Requirements"] --> ProjectType{"Project Type?"}

    ProjectType -->|"Simple Library"| SimpleLib["Simple Library Rules"]
    ProjectType -->|"Complex Application"| ComplexApp["Complex Application Rules"]
    ProjectType -->|"CLI Tool"| CLITool["CLI Tool Rules"]
    ProjectType -->|"Web Service"| WebService["Web Service Rules"]

    SimpleLib --> BasicRules["Basic Quality Rules"]
    ComplexApp --> AdvancedRules["Advanced Quality Rules"]
    CLITool --> BasicRules
    WebService --> AdvancedRules

    BasicRules --> Naming["Naming Strategy"]
    AdvancedRules --> Naming

    Naming --> NamingRules["• Functionality-based files<br>• Descriptive specific names<br>• No implementation suffixes"]

    NamingRules --> Structure["Code Structure"]

    Structure --> StructureRules["• File-based organization<br>• Size limitations (500 lines)<br>• Single responsibility<br>• Function size (150 lines)"]

    StructureRules --> Safety["Safety Requirements"]

    Safety --> SafetyRules["• Rust 2024 edition<br>• No unsafe code<br>• No unwrap() in production<br>• Proper error handling"]

    SafetyRules --> Testing["Testing Strategy"]

    Testing --> TestingRules["• Unit tests same file<br>• Integration tests separate<br>• Doc tests with examples"]

    TestingRules --> Verification["Quality Verification"]

    Verification --> Build["cargo build"]
    Verification --> Test["cargo test"]
    Verification --> Clippy["cargo clippy"]

    Build --> AllPass{"All Pass?"}
    Test --> AllPass
    Clippy --> AllPass

    AllPass -->|"Yes"| Success["✅ Quality Standards Met"]
    AllPass -->|"No"| FixIssues["🔧 Fix Issues"]

    FixIssues --> Verification

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style ProjectType fill:#ffa64d,stroke:#cc7a30,color:white
    style SimpleLib fill:#4dbb5f,stroke:#36873f,color:white
    style ComplexApp fill:#d94dbb,stroke:#a3378a,color:white
    style CLITool fill:#9f4dbb,stroke:#7a3787,color:white
    style WebService fill:#bb4d4d,stroke:#873636,color:white
    style BasicRules fill:#bbbb4d,stroke:#878736,color:white
    style AdvancedRules fill:#4dbbbb,stroke:#368787,color:white
    style Success fill:#5fbb5f,stroke:#4a8f4a,color:white
    style FixIssues fill:#ff6b6b,stroke:#cc5555,color:white
```

## 🎯 FUNDAMENTAL PRINCIPLES

### Code Organization
- **Functionality-based files**: Use meaningful file names like `user.rs`, `product.rs`, `auth.rs` instead of generic `models.rs`, `traits.rs`, `types.rs`
- **Meaningful naming**: Avoid names like `UserServiceImpl` - use descriptive, specific names
- **File size limits**: Maximum 500 lines per file (excluding tests)
- **Function size**: Maximum 150 lines per function
- **Single Responsibility**: Each module should have one clear purpose

### Rust Edition and Safety
- **Always use Rust 2024 edition**
- **Never use `unsafe` code** - find safe alternatives
- **Production-ready code**: All code must be deployable and maintainable
- **No `unwrap()` or `expect()`** in production code - use proper error handling

## 🏗️ CODE STRUCTURE PATTERNS

### Data Structure Organization
```rust
// ✅ Good: Functionality-based organization
// src/user.rs - All user-related types and logic
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]  // Always use camelCase for JSON serialization
pub struct User {
    pub user_id: String,
    pub display_name: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

// ✅ Good: Meaningful trait names
pub trait UserValidator {
    fn validate(&self, user: &User) -> Result<(), ValidationError>;
}

// ❌ Bad: Generic file organization
// src/models.rs, src/traits.rs, src/types.rs
// ❌ Bad: Poor naming
// struct UserValidatorImpl
```

### Serde Configuration
```rust
// ✅ Always use camelCase for JSON serialization
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse {
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

// This serializes to:
// {"userId": "...", "createdAt": "...", "isActive": true}
```

## 🔧 BUILD AND QUALITY CHECKS

### Mandatory Verification Steps
After completing any code changes, **always run in order**:

```bash
# 1. Build check
cargo build

# 2. Test execution
cargo test

# 3. Linting
cargo clippy

# All must pass before considering code complete
```

### Clippy Configuration
```toml
# Cargo.toml
[lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
unwrap_used = "deny"
expect_used = "deny"
```

## 🗂️ FILE NAMING CONVENTIONS

### Module Organization Patterns
```rust
// ✅ Good: Feature-based modules
src/
├── user/
│   ├── mod.rs
│   ├── service.rs       // UserService logic
│   ├── repository.rs    // User data access
│   └── validator.rs     // User validation
├── product/
│   ├── mod.rs
│   ├── catalog.rs       // Product catalog logic
│   └── pricing.rs       // Product pricing logic
└── auth/
    ├── mod.rs
    ├── token.rs         // Token management
    └── session.rs       // Session handling
```

### Naming Best Practices
```rust
// ✅ Good naming examples
pub struct UserService;                // Clear, specific
pub struct ProductCatalog;             // Action-oriented
pub struct DatabaseConnection;         // Descriptive

// ❌ Bad naming examples
pub struct UserServiceImpl;            // Unnecessary "Impl" suffix
pub struct Helper;                     // Too generic
pub struct Manager;                    // Vague responsibility
```

## 🧪 TESTING STANDARDS

### Unit Test Placement
```rust
// ✅ Always place unit tests in the same file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_validation() {
        let validator = UserValidator::new();
        let user = User::default();
        assert!(validator.validate(&user).is_ok());
    }
}

// ❌ Don't create separate test files for unit tests
// tests/user_test.rs (this is for integration tests only)
```

### Test Naming
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email_passes_validation() {
        // Test name clearly describes the scenario
    }

    #[test]
    fn test_empty_email_returns_error() {
        // Specific about what's being tested
    }
}
```

## 📝 DOCUMENTATION STANDARDS

### Code Documentation
```rust
/// Validates user data according to business rules.
///
/// # Examples
///
/// ```rust
/// let validator = UserValidator::new();
/// let user = User::builder()
///     .email("user@example.com")
///     .display_name("John Doe")
///     .build();
///
/// assert!(validator.validate(&user).is_ok());
/// ```
///
/// # Errors
///
/// Returns `ValidationError` if:
/// - Email is empty or invalid format
/// - Display name is too long
/// - Required fields are missing
pub struct UserValidator {
    rules: Vec<ValidationRule>,
}
```

## 🚨 ANTI-PATTERNS TO AVOID

### Code Organization Anti-Patterns
```rust
// ❌ Don't use generic file names
// src/models.rs - mixing unrelated types
// src/utils.rs - catch-all for random functions
// src/helpers.rs - unclear responsibility

// ❌ Don't use implementation suffixes
pub struct UserValidatorImpl;
pub struct DatabaseManagerImpl;

// ❌ Don't mix concerns in single files
// src/app.rs containing database, validation, and HTTP logic

// ❌ Don't use overly long files
// Any file > 500 lines (excluding tests) needs refactoring
```

## ✅ QUALITY CHECKLIST

```markdown
### Code Quality Verification
- [ ] Uses Rust 2024 edition
- [ ] No `unsafe` code blocks
- [ ] No `unwrap()` or `expect()` in production code
- [ ] All data structures use `#[serde(rename_all = "camelCase")]`
- [ ] Files organized by functionality, not type
- [ ] Meaningful names (no "Impl" suffixes)
- [ ] Functions ≤ 150 lines
- [ ] Files ≤ 500 lines (excluding tests)
- [ ] Unit tests in same file as implementation
- [ ] `cargo build` passes
- [ ] `cargo test` passes
- [ ] `cargo clippy` passes with no warnings
- [ ] Public APIs documented with examples
```

This code quality standard ensures consistent, maintainable, and production-ready Rust code across all projects.

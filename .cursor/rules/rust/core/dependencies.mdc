---
description:
globs:
alwaysApply: false
---
# 📦 RUST DEPENDENCY MANAGEMENT

> **TL;DR:** Centralized dependency management guidelines for consistent, secure, and maintainable Rust projects.

## 🔍 DEPENDENCY MANAGEMENT STRATEGY

```mermaid
graph TD
    Start["Project Setup"] --> WorkspaceCheck{"Workspace<br>Project?"}

    WorkspaceCheck -->|Yes| WorkspaceRoot["Use Workspace Dependencies"]
    WorkspaceCheck -->|No| SingleCrate["Single Crate Dependencies"]

    WorkspaceRoot --> WorkspaceTable["[workspace.dependencies]<br>Define versions centrally"]
    SingleCrate --> DirectDeps["[dependencies]<br>Direct version specification"]

    WorkspaceTable --> CrateUsage["[dependencies]<br>crate = { workspace = true }"]

    CrateUsage --> SecurityCheck["Security Assessment"]
    DirectDeps --> SecurityCheck

    SecurityCheck --> Audit["cargo audit"]
    Audit --> Outdated["cargo outdated"]
    Outdated --> VersionPin["Pin Critical Versions"]

    VersionPin --> FeatureGates["Feature Gate Optional Deps"]
    FeatureGates --> Testing["Testing Dependencies"]
    Testing --> Documentation["Document Choices"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style WorkspaceRoot fill:#4dbb5f,stroke:#36873f,color:white
    style SingleCrate fill:#ffa64d,stroke:#cc7a30,color:white
    style SecurityCheck fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 DEPENDENCY STRATEGY

### Workspace Dependencies Priority
```toml
# Always prefer workspace dependencies first
[dependencies]
tokio = { workspace = true }
serde = { workspace = true, features = ["derive"] }

# Only add new dependencies if not available in workspace
# Request permission before modifying Cargo.toml
```

## 📋 STANDARD CRATE RECOMMENDATIONS

### Core Utilities
```toml
# Error handling
anyhow = "1.0"                               # Simple error handling
thiserror = "2.0"                           # Structured error types
derive_more = { version = "2", features = ["full"] }  # Extended derive macros

# Data structures
typed-builder = "0.21"                      # Builder pattern
uuid = { version = "1.17", features = ["v4", "v7", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
time = { version = "0.3", features = ["serde"] }
```

### Async/Concurrency
```toml
tokio = { version = "1.45", features = [
    "macros",
    "rt-multi-thread",
    "signal",
    "sync",
    "fs",
    "net",
    "time"
] }
async-trait = "0.1"                         # Async traits
futures = "0.3"                             # Async utilities
dashmap = { version = "6", features = ["serde"] }  # Concurrent HashMap
```

### Serialization
```toml
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"
base64 = "0.22"
```

### Web/HTTP
```toml
axum = { version = "0.8", features = ["macros", "http2", "multipart"] }
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
tower = { version = "0.5", features = ["util", "timeout", "load-shed"] }
tower-http = { version = "0.6", features = ["cors", "trace", "compression"] }
http = "1.0"
```

### Database
```toml
sqlx = { version = "0.8", features = [
    "chrono",
    "postgres",
    "runtime-tokio-rustls",
    "sqlite",
    "time",
    "uuid",
    "json"
] }
```

### Documentation/API
```toml
utoipa = { version = "5", features = ["axum_extras", "chrono", "uuid"] }
utoipa-axum = "0.2"
utoipa-swagger-ui = { version = "9", features = [
    "axum",
    "vendored"
], default-features = false }
schemars = { version = "0.8", features = ["chrono", "url"] }
```

### CLI Applications
```toml
clap = { version = "4.0", features = ["derive", "env", "unicode"] }
dialoguer = "0.11"                          # Interactive prompts
indicatif = "0.17"                          # Progress bars
colored = "2.0"                             # Terminal colors
console = "0.15"                            # Terminal utilities
```

### Configuration Management
```toml
figment = { version = "0.10", features = ["yaml", "toml", "env"] }
notify = "6.0"                              # File watching
arc-swap = "1.0"                            # Atomic configuration updates
validator = { version = "0.18", features = ["derive"] }
```

### Observability
```toml
prometheus = "0.13"                         # Metrics collection
opentelemetry = "0.23"                      # Distributed tracing
tracing-opentelemetry = "0.23"              # Tracing integration
dashmap = "6.0"                             # Lock-free concurrent maps
```

### Frontend Integration
```toml
rust-embed = "8.0"                          # Static asset embedding
mime_guess = "2.0"                          # MIME type detection
```

### gRPC/Protobuf
```toml
tonic = { version = "0.13", features = ["transport", "codegen", "prost"] }
prost = "0.13"
prost-types = "0.13"
tonic-build = "0.13"
prost-build = "0.13"
tonic-health = "0.13"
tonic-reflection = "0.13"
```

### Development/Testing
```toml
[dev-dependencies]
tempfile = "3.0"                            # Temporary files
wiremock = "0.6"                            # HTTP mocking
assert_cmd = "2.0"                          # CLI testing
predicates = "3.0"                          # Test assertions
axum-test = "15.0"                          # Axum testing
tokio-test = "0.4"                          # Tokio testing utilities
temp-env = "0.3"                            # Environment variable testing
```

## 🔧 FEATURE FLAG STRATEGY

### Minimal Feature Sets
```toml
# ✅ Good: Only enable needed features
reqwest = { version = "0.12", default-features = false, features = [
    "rustls-tls-webpki-roots",  # TLS support
    "json",                     # JSON serialization
    "gzip"                      # Compression
] }

# ❌ Bad: Enabling all features
# reqwest = { version = "0.12", features = ["full"] }
```

### Feature Documentation
```toml
# Document why each feature is needed
tokio = { version = "1.45", features = [
    "macros",          # #[tokio::main] and #[tokio::test]
    "rt-multi-thread", # Multi-threaded runtime
    "signal",          # Signal handling for graceful shutdown
    "net",             # Network primitives
    "fs",              # File system operations
    "time"             # Time utilities
] }
```

## 🔒 SECURITY CONSIDERATIONS

### TLS Configuration
```toml
# ✅ Prefer rustls over openssl
reqwest = { version = "0.12", default-features = false, features = [
    "rustls-tls-webpki-roots"  # Use rustls with web PKI roots
] }

# ❌ Avoid native-tls when possible
# reqwest = { version = "0.12", features = ["native-tls"] }
```

### Crypto Dependencies
```toml
# Use well-established crypto crates
rand = { version = "0.8", features = ["std_rng"] }
getrandom = { version = "0.3", features = ["std"] }
jsonwebtoken = "9.0"
argon2 = "0.15"
```

## 📊 VERSION STRATEGY

### Version Selection Rules
1. **Always use latest stable versions** for new dependencies
2. **Use semantic versioning** - prefer `"1.0"` over `"=1.0.0"`
3. **Check workspace first** - never duplicate dependencies
4. **Document breaking changes** when updating major versions

### Workspace Version Management
```toml
# workspace Cargo.toml
[workspace.dependencies]
tokio = { version = "1.45", features = ["macros", "rt-multi-thread"] }
serde = { version = "1.0", features = ["derive"] }
anyhow = "1.0"
thiserror = "2.0"
uuid = { version = "1.17", features = ["v4", "serde"] }

# Individual crate Cargo.toml
[dependencies]
tokio = { workspace = true, features = ["signal"] }  # Add extra features as needed
serde = { workspace = true }
anyhow = { workspace = true }
```

## 🚨 DEPENDENCY ANTI-PATTERNS

### What to Avoid
```toml
# ❌ Don't duplicate workspace dependencies
[dependencies]
tokio = "1.0"  # Already in workspace

# ❌ Don't enable unnecessary features
tokio = { version = "1.45", features = ["full"] }  # Too broad

# ❌ Don't use outdated versions
serde = "0.9"  # Use latest stable

# ❌ Don't mix TLS implementations
reqwest = { version = "0.12", features = ["native-tls", "rustls-tls"] }

# ❌ Don't use git dependencies in production
my-crate = { git = "https://github.com/user/repo" }
```

### Common Mistakes
```rust
// ❌ Don't import with wildcard
use serde::*;

// ✅ Import specific items
use serde::{Deserialize, Serialize};

// ❌ Don't use deprecated APIs
use std::sync::ONCE_INIT;  // Deprecated

// ✅ Use modern alternatives
use std::sync::Once;
```

## 📝 DEPENDENCY AUDIT

### Regular Maintenance
```bash
# Check for outdated dependencies
cargo outdated

# Audit for security vulnerabilities
cargo audit

# Check for unused dependencies
cargo machete

# Update dependencies
cargo update
```

### Security Best Practices
```toml
# Pin security-critical dependencies
openssl = "=0.10.64"  # Pin exact version for security

# Use cargo-deny for policy enforcement
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
```

## ✅ DEPENDENCY CHECKLIST

```markdown
### Dependency Management Verification
- [ ] Uses workspace dependencies when available
- [ ] Features flags are minimal and documented
- [ ] Prefers rustls over native-tls
- [ ] Uses latest stable versions
- [ ] Security-critical deps are audited
- [ ] No duplicate dependencies across workspace
- [ ] Dev dependencies separated from runtime deps
- [ ] Feature documentation explains necessity
- [ ] Regular dependency updates scheduled
- [ ] Vulnerability scanning enabled
```

This dependency management guide ensures consistent, secure, and maintainable dependency choices across all Rust projects.

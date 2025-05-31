---
description:
globs:
alwaysApply: false
---
# 📦 SINGLE CRATE PROJECT STRUCTURE

> **TL;DR:** Guidelines for organizing simple Rust projects using a single crate structure with clean separation of concerns and maintainable file organization.

## 🔍 SINGLE CRATE DESIGN STRATEGY

```mermaid
graph TD
    Start["Single Crate Project"] --> CrateType{"Crate<br>Type?"}

    CrateType -->|Binary| BinaryStructure["Binary Crate Structure"]
    CrateType -->|Library| LibraryStructure["Library Crate Structure"]
    CrateType -->|Mixed| MixedStructure["Mixed Crate Structure"]

    BinaryStructure --> MinimalMain["Minimal main.rs"]
    BinaryStructure --> CoreLib["Core Logic in lib.rs"]

    LibraryStructure --> PublicAPI["Public API Design"]
    LibraryStructure --> ModuleOrg["Module Organization"]

    MixedStructure --> BinaryEntry["Binary Entry Point"]
    MixedStructure --> LibraryAPI["Library API"]

    MinimalMain --> FeatureModules["Feature-Based Modules"]
    CoreLib --> FeatureModules
    PublicAPI --> FeatureModules
    ModuleOrg --> FeatureModules
    BinaryEntry --> FeatureModules
    LibraryAPI --> FeatureModules

    FeatureModules --> ErrorHandling["Centralized Error Handling"]
    ErrorHandling --> Configuration["Configuration Management"]
    Configuration --> Testing["Testing Strategy"]
    Testing --> Documentation["Documentation"]

    Documentation --> Production["Production Single Crate"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style BinaryStructure fill:#4dbb5f,stroke:#36873f,color:white
    style LibraryStructure fill:#ffa64d,stroke:#cc7a30,color:white
    style MixedStructure fill:#d94dbb,stroke:#a3378a,color:white
```

## 🏗️ PROJECT STRUCTURE OVERVIEW

```mermaid
graph TD
    Project["Single Crate Project"] --> Binary["Binary Crate<br>(src/main.rs)"]
    Project --> Library["Library Crate<br>(src/lib.rs)"]
    Project --> Mixed["Mixed Crate<br>(src/main.rs + src/lib.rs)"]

    Binary --> BinStructure["Binary Structure:"]
    Library --> LibStructure["Library Structure:"]
    Mixed --> MixedStructure["Mixed Structure:"]

    BinStructure --> MainRs["src/main.rs<br>(minimal)"]
    BinStructure --> AppLib["src/lib.rs<br>(core logic)"]
    BinStructure --> Modules["src/modules/<br>(feature modules)"]

    LibStructure --> LibRs["src/lib.rs<br>(public API)"]
    LibStructure --> LibModules["src/modules/<br>(functionality)"]
    LibStructure --> LibErrors["src/errors.rs<br>(centralized errors)"]

    MixedStructure --> BothMain["src/main.rs<br>(binary entry)"]
    MixedStructure --> BothLib["src/lib.rs<br>(library API)"]
    MixedStructure --> SharedMods["src/modules/<br>(shared logic)"]

    style Project fill:#4da6ff,stroke:#0066cc,color:white
    style Binary fill:#4dbb5f,stroke:#36873f,color:white
    style Library fill:#ffa64d,stroke:#cc7a30,color:white
    style Mixed fill:#d94dbb,stroke:#a3378a,color:white
```

## 📁 RECOMMENDED FILE STRUCTURE

### Binary Crate Structure

```
my_project/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs           # Entry point (minimal, delegates to lib.rs)
│   ├── lib.rs            # Core application logic
│   ├── errors.rs         # Centralized error definitions
│   ├── config.rs         # Configuration handling
│   ├── cli.rs            # Command-line interface (if applicable)
│   └── modules/          # Feature-based modules
│       ├── mod.rs        # Module declarations
│       ├── auth.rs       # Authentication logic
│       ├── database.rs   # Database operations
│       └── handlers.rs   # Request/command handlers
├── tests/                # Integration tests
│   └── integration_test.rs
└── examples/             # Usage examples
    └── basic_usage.rs
```

### Library Crate Structure

```
my_lib/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs            # Public API and module declarations
│   ├── errors.rs         # Error types (using thiserror)
│   └── modules/          # Functionality modules
│       ├── mod.rs        # Module re-exports
│       ├── core.rs       # Core functionality
│       ├── utils.rs      # Utility functions
│       └── types.rs      # Public type definitions
├── tests/                # Integration tests
│   └── lib_test.rs
├── examples/             # Usage examples
│   └── quick_start.rs
└── benches/              # Benchmarks (optional)
    └── benchmark.rs
```

## 🎯 BINARY CRATE PATTERNS

### Minimal main.rs Pattern

```rust
// src/main.rs - Keep this minimal and delegate to lib.rs
use anyhow::Result;

fn main() -> Result<()> {
    my_project::run()
}
```

### Comprehensive lib.rs for Binary

```rust
// src/lib.rs - Contains the main application logic
mod config;
mod errors;
mod cli;
mod modules;

pub use errors::AppError;
use config::Config;
use anyhow::{Context, Result};

/// Main application entry point
pub fn run() -> Result<()> {
    let config = Config::load()
        .context("Failed to load configuration")?;

    let app = Application::new(config)?;
    app.start()
        .context("Application failed to start")?;

    Ok(())
}

/// Core application struct
pub struct Application {
    config: Config,
    // Other application state
}

impl Application {
    pub fn new(config: Config) -> Result<Self> {
        // Initialize application
        Ok(Self { config })
    }

    pub fn start(&self) -> Result<()> {
        // Main application logic
        println!("Application started with config: {:?}", self.config);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_creation() {
        let config = Config::default();
        let app = Application::new(config);
        assert!(app.is_ok());
    }
}
```

### Configuration Module Pattern

```rust
// src/config.rs
use serde::{Deserialize, Serialize};
use std::env;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub database_url: String,
    pub server_port: u16,
    pub log_level: String,
    pub debug_mode: bool,
}

impl Config {
    pub fn load() -> Result<Self> {
        // Try environment variables first
        if let Ok(config) = Self::from_env() {
            return Ok(config);
        }

        // Fall back to config file
        Self::from_file("config.toml")
            .context("Failed to load configuration from file")
    }

    fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?,
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .context("Invalid SERVER_PORT")?,
            log_level: env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            debug_mode: env::var("DEBUG_MODE")
                .map(|v| v.parse().unwrap_or(false))
                .unwrap_or(false),
        })
    }

    fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;

        toml::from_str(&content)
            .context("Failed to parse config file")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: "sqlite::memory:".to_string(),
            server_port: 8080,
            log_level: "info".to_string(),
            debug_mode: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server_port, 8080);
        assert_eq!(config.log_level, "info");
        assert!(!config.debug_mode);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.server_port, deserialized.server_port);
    }
}
```

## 📚 LIBRARY CRATE PATTERNS

### Public API lib.rs Pattern

```rust
// src/lib.rs - Clean public API
//! # My Library
//!
//! This library provides functionality for...
//!
//! ## Quick Start
//!
//! ```rust
//! use my_lib::MyStruct;
//!
//! let instance = MyStruct::new("example")?;
//! let result = instance.process()?;
//! ```

mod modules;
mod errors;

// Public API exports
pub use errors::{MyLibError, Result};
pub use modules::{
    core::{MyStruct, ProcessResult},
    utils::{helper_function, UtilityTrait},
};

// Re-export commonly used types
pub use modules::types::{PublicType, Configuration};

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the library with default settings
pub fn init() -> Result<()> {
    // Library initialization logic
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_initialization() {
        assert!(init().is_ok());
    }

    #[test]
    fn test_version_info() {
        assert!(!VERSION.is_empty());
    }
}
```

### Module Organization Pattern

```rust
// src/modules/mod.rs
pub mod core;
pub mod utils;
pub mod types;

// Re-export for internal use
pub(crate) use core::*;
pub(crate) use utils::*;
pub(crate) use types::*;
```

```rust
// src/modules/core.rs
use crate::errors::{MyLibError, Result};
use crate::modules::types::Configuration;

/// Main functionality struct
#[derive(Debug, Clone)]
pub struct MyStruct {
    config: Configuration,
    data: String,
}

impl MyStruct {
    /// Create a new instance
    pub fn new(data: impl Into<String>) -> Result<Self> {
        let data = data.into();
        if data.is_empty() {
            return Err(MyLibError::invalid_input("Data cannot be empty"));
        }

        Ok(Self {
            config: Configuration::default(),
            data,
        })
    }

    /// Process the data
    pub fn process(&self) -> Result<ProcessResult> {
        // Main processing logic
        let processed = self.data.to_uppercase();

        Ok(ProcessResult {
            original: self.data.clone(),
            processed,
            metadata: self.config.clone(),
        })
    }

    /// Update configuration
    pub fn with_config(mut self, config: Configuration) -> Self {
        self.config = config;
        self
    }
}

/// Result of processing operation
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessResult {
    pub original: String,
    pub processed: String,
    pub metadata: Configuration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mystruct_creation() {
        let instance = MyStruct::new("test").unwrap();
        assert_eq!(instance.data, "test");
    }

    #[test]
    fn test_empty_data_error() {
        let result = MyStruct::new("");
        assert!(result.is_err());
    }

    #[test]
    fn test_processing() {
        let instance = MyStruct::new("hello").unwrap();
        let result = instance.process().unwrap();
        assert_eq!(result.processed, "HELLO");
        assert_eq!(result.original, "hello");
    }

    #[test]
    fn test_with_config() {
        let config = Configuration::new("custom");
        let instance = MyStruct::new("test")
            .unwrap()
            .with_config(config.clone());

        let result = instance.process().unwrap();
        assert_eq!(result.metadata, config);
    }
}
```

## 🔧 CARGO.TOML CONFIGURATION

### Binary Crate Cargo.toml

```toml
[package]
name = "my_project"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <your.email@example.com>"]
description = "A brief description of your project"
readme = "README.md"
repository = "https://github.com/yourusername/my_project"
license = "MIT OR Apache-2.0"
keywords = ["cli", "tool", "utility"]
categories = ["command-line-utilities"]

[dependencies]
anyhow = "1.0"
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"
clap = { version = "4.0", features = ["derive"] }

[dev-dependencies]
tempfile = "3.0"

[[bin]]
name = "my_project"
path = "src/main.rs"

[profile.release]
lto = true
codegen-units = 1
panic = "abort"
```

### Library Crate Cargo.toml

```toml
[package]
name = "my_lib"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <your.email@example.com>"]
description = "A useful library for..."
readme = "README.md"
repository = "https://github.com/yourusername/my_lib"
license = "MIT OR Apache-2.0"
keywords = ["library", "utility", "parsing"]
categories = ["development-tools"]

[dependencies]
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }

[dev-dependencies]
serde_json = "1.0"

[lib]
name = "my_lib"
path = "src/lib.rs"

[features]
default = []
extra_features = ["serde"]

[[example]]
name = "quick_start"
path = "examples/quick_start.rs"
```

## 📝 SINGLE CRATE CHECKLIST

```markdown
## Single Crate Structure Verification

### Project Setup
- [ ] Appropriate crate type chosen (bin/lib/mixed)
- [ ] Cargo.toml properly configured
- [ ] README.md with clear documentation
- [ ] License file included

### File Organization
- [ ] src/main.rs minimal (for binary crates)
- [ ] src/lib.rs contains core logic
- [ ] src/errors.rs centralizes error definitions
- [ ] Feature modules in src/modules/
- [ ] Each file ≤ 500 lines (excluding tests)

### Code Quality
- [ ] Functions ≤ 150 lines
- [ ] Functionality-based file organization
- [ ] Comprehensive unit tests in each file
- [ ] Public API well-documented
- [ ] Error handling consistent throughout

### Testing
- [ ] Unit tests in each module
- [ ] Integration tests in tests/ directory
- [ ] Examples in examples/ directory
- [ ] All public APIs tested

### Documentation
- [ ] Public APIs documented with /// comments
- [ ] Examples included in documentation
- [ ] README with usage instructions
- [ ] Changelog for version tracking
```

## 🚨 COMMON ANTI-PATTERNS TO AVOID

### ❌ Don't Do This

```rust
// ❌ Fat main.rs with business logic
fn main() {
    // Hundreds of lines of business logic
    let config = load_config();
    let database = connect_database();
    // ... more logic
}

// ❌ Type-based file organization
// src/types.rs - All types mixed together
// src/traits.rs - All traits mixed together
// src/impls.rs - All implementations mixed together

// ❌ Single massive file
// src/lib.rs with 2000+ lines of mixed functionality
```

### ✅ Do This Instead

```rust
// ✅ Minimal main.rs
fn main() -> anyhow::Result<()> {
    my_project::run()
}

// ✅ Function-based organization
// src/auth.rs - Authentication-related types, traits, and implementations
// src/database.rs - Database-related functionality
// src/config.rs - Configuration handling

// ✅ Modular lib.rs
// src/lib.rs - Clean public API with module re-exports
// src/modules/ - Separate files for different functionality
```

This single crate structure provides a solid foundation for simple Rust projects while maintaining clean organization and scalability.

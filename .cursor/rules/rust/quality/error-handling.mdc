---
description:
globs:
alwaysApply: false
---
# 🚨 RUST ERROR HANDLING STANDARDS

> **TL;DR:** Comprehensive error handling guidelines using thiserror for libraries and anyhow for binaries, with centralized error definitions per crate.

## 🔍 ERROR HANDLING STRATEGY SELECTION

```mermaid
graph TD
    Project["Project Analysis"] --> CrateType{"Crate Type?"}

    CrateType -->|"lib"| LibCrate["Library Crate"]
    CrateType -->|"bin"| BinCrate["Binary Crate"]

    LibCrate --> ThiserrorChoice["Use thiserror"]
    BinCrate --> AnyhowChoice["Use anyhow"]

    ThiserrorChoice --> LibFeatures["Library Features:"]
    AnyhowChoice --> BinFeatures["Binary Features:"]

    LibFeatures --> Structured["• Structured errors"]
    LibFeatures --> Derived["• Derive Error trait"]
    LibFeatures --> Transparent["• Error forwarding"]
    LibFeatures --> Documentation["• Error documentation"]

    BinFeatures --> Simple["• Simple error handling"]
    BinFeatures --> Context["• Rich context"]
    BinFeatures --> Chaining["• Error chaining"]
    BinFeatures --> EndUser["• End-user messages"]

    style Project fill:#4da6ff,stroke:#0066cc,color:white
    style CrateType fill:#ffa64d,stroke:#cc7a30,color:white
    style LibCrate fill:#4dbb5f,stroke:#36873f,color:white
    style BinCrate fill:#d94dbb,stroke:#a3378a,color:white
```

## 📚 LIBRARY CRATE ERROR HANDLING (thiserror)

### Error Definition Pattern

```rust
// lib_crate/src/errors.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MyLibError {
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("File not found: {path}")]
    FileNotFound { path: String },

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Network error")]
    Network(#[from] reqwest::Error),

    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("Internal error: {0}")]
    Internal(String),
}

// Additional result type alias for convenience
pub type Result<T> = std::result::Result<T, MyLibError>;

// Error construction helpers
impl MyLibError {
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    pub fn file_not_found(path: impl Into<String>) -> Self {
        Self::FileNotFound {
            path: path.into(),
        }
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}
```

### Usage in Library Functions

```rust
// lib_crate/src/lib.rs
use crate::errors::{MyLibError, Result};

pub fn process_file(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(MyLibError::invalid_input("Path cannot be empty"));
    }

    let content = std::fs::read_to_string(path)
        .map_err(|_| MyLibError::file_not_found(path))?;

    if content.is_empty() {
        return Err(MyLibError::invalid_input("File is empty"));
    }

    Ok(content.to_uppercase())
}

pub fn parse_config(data: &str) -> Result<Config> {
    // The #[from] attribute automatically converts serde_json::Error
    let config: Config = serde_json::from_str(data)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_path_error() {
        let result = process_file("");
        assert!(matches!(result, Err(MyLibError::InvalidInput { .. })));
    }

    #[test]
    fn test_file_not_found_error() {
        let result = process_file("nonexistent.txt");
        assert!(matches!(result, Err(MyLibError::FileNotFound { .. })));
    }
}
```

## 🏃 BINARY CRATE ERROR HANDLING (anyhow)

### Error Definition Pattern

```rust
// bin_crate/src/errors.rs
use anyhow::{Context, Result};
use thiserror::Error;

// Define application-specific errors that need structure
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("User error: {message}")]
    User { message: String },

    #[error("System error: {message}")]
    System { message: String },
}

// Helper functions for common error patterns
pub fn config_error(message: impl Into<String>) -> AppError {
    AppError::Config {
        message: message.into(),
    }
}

pub fn user_error(message: impl Into<String>) -> AppError {
    AppError::User {
        message: message.into(),
    }
}

pub fn system_error(message: impl Into<String>) -> AppError {
    AppError::System {
        message: message.into(),
    }
}

// Type alias for the main Result type
pub type AppResult<T> = Result<T>;
```

### Usage in Binary Application

```rust
// bin_crate/src/main.rs
use anyhow::{Context, Result, bail, ensure};
use crate::errors::{AppResult, user_error, config_error};

fn main() -> Result<()> {
    let config = load_config()
        .context("Failed to load application configuration")?;

    let result = process_data(&config)
        .context("Failed to process data")?;

    save_results(&result)
        .context("Failed to save results")?;

    println!("Processing completed successfully");
    Ok(())
}

fn load_config() -> AppResult<Config> {
    let config_path = std::env::var("CONFIG_PATH")
        .context("CONFIG_PATH environment variable not set")?;

    ensure!(!config_path.is_empty(), config_error("Config path is empty"));

    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path))?;

    let config: Config = toml::from_str(&content)
        .context("Failed to parse config file as TOML")?;

    Ok(config)
}

fn process_data(config: &Config) -> AppResult<ProcessResult> {
    if config.input_files.is_empty() {
        bail!(user_error("No input files specified"));
    }

    let mut results = Vec::new();

    for file_path in &config.input_files {
        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read input file: {}", file_path))?;

        let processed = process_file_content(&content)
            .with_context(|| format!("Failed to process file: {}", file_path))?;

        results.push(processed);
    }

    Ok(ProcessResult { results })
}

fn process_file_content(content: &str) -> Result<String> {
    ensure!(!content.is_empty(), "File content is empty");

    // Complex processing logic that might fail
    let processed = content
        .lines()
        .map(|line| process_line(line))
        .collect::<Result<Vec<_>>>()?
        .join("\n");

    Ok(processed)
}

fn process_line(line: &str) -> Result<String> {
    if line.trim().is_empty() {
        return Ok(String::new());
    }

    // Some processing that might fail
    Ok(line.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_line_success() {
        let result = process_line("hello world").unwrap();
        assert_eq!(result, "HELLO WORLD");
    }

    #[test]
    fn test_process_empty_line() {
        let result = process_line("").unwrap();
        assert_eq!(result, "");
    }
}
```

## 🔄 ERROR HANDLING WORKFLOW

```mermaid
sequenceDiagram
    participant Code as Application Code
    participant Lib as Library
    participant Error as Error Handler
    participant User as End User

    Code->>Lib: Call library function
    Lib->>Lib: Process request

    alt Success Case
        Lib->>Code: Return Ok(result)
        Code->>User: Success response
    else Library Error (thiserror)
        Lib->>Code: Return Err(LibError)
        Code->>Error: Convert to anyhow
        Error->>Error: Add context
        Error->>User: Formatted error message
    else System Error
        Lib->>Code: Return Err(SystemError)
        Code->>Error: Add application context
        Error->>User: User-friendly message
    end
```

## 📋 ERROR CATEGORIES AND HANDLING

```mermaid
graph TD
    Error["Error Occurred"] --> Category["Categorize Error"]

    Category --> Recoverable["Recoverable<br>Error"]
    Category --> Fatal["Fatal<br>Error"]
    Category --> User["User<br>Error"]
    Category --> System["System<br>Error"]

    Recoverable --> Retry["Implement<br>Retry Logic"]
    Recoverable --> Fallback["Provide<br>Fallback"]

    Fatal --> Cleanup["Cleanup<br>Resources"]
    Fatal --> Exit["Exit<br>Gracefully"]

    User --> Validate["Validate<br>Input"]
    User --> Feedback["Provide<br>Feedback"]

    System --> Log["Log<br>Error"]
    System --> Alert["Alert<br>Operators"]

    style Error fill:#4da6ff,stroke:#0066cc,color:white
    style Recoverable fill:#4dbb5f,stroke:#36873f,color:white
    style Fatal fill:#d94dbb,stroke:#a3378a,color:white
    style User fill:#ffa64d,stroke:#cc7a30,color:white
    style System fill:#4dbbbb,stroke:#368787,color:white
```

## 🛠️ ERROR HANDLING PATTERNS

### Pattern 1: Early Return with Context

```rust
fn complex_operation(input: &str) -> Result<ProcessedData> {
    let validated = validate_input(input)
        .context("Input validation failed")?;

    let parsed = parse_data(&validated)
        .context("Failed to parse input data")?;

    let transformed = transform_data(parsed)
        .context("Data transformation failed")?;

    let result = finalize_data(transformed)
        .context("Failed to finalize processing")?;

    Ok(result)
}
```

### Pattern 2: Error Mapping

```rust
fn convert_external_error() -> Result<String> {
    external_library::fetch_data()
        .map_err(|e| anyhow::anyhow!("External service failed: {}", e))?;

    Ok("success".to_string())
}
```

### Pattern 3: Conditional Error Handling

```rust
fn conditional_processing(config: &Config) -> Result<()> {
    if config.strict_mode {
        process_strictly()
            .context("Strict processing failed")?;
    } else {
        match process_leniently() {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Warning: Lenient processing failed: {}", e);
                default_result()
            }
        }
    }

    Ok(())
}
```

## 📝 ERROR HANDLING CHECKLIST

```markdown
## Error Handling Verification

### Library Crates (thiserror)
- [ ] All errors defined in centralized errors.rs
- [ ] Error types derive Error, Debug
- [ ] Meaningful error messages with #[error]
- [ ] Proper use of #[from] for conversions
- [ ] Helper constructors for complex errors
- [ ] Result type alias defined
- [ ] Comprehensive error documentation

### Binary Crates (anyhow)
- [ ] anyhow::Result used consistently
- [ ] Context added to all error chains
- [ ] User-friendly error messages
- [ ] Proper cleanup on fatal errors
- [ ] Structured errors for app-specific cases
- [ ] Graceful error handling in main()

### General
- [ ] No unwrap() or expect() in production code
- [ ] Errors properly propagated
- [ ] Error tests included
- [ ] Error logging implemented
- [ ] Recovery strategies defined
```

## 🚨 ANTI-PATTERNS TO AVOID

### ❌ Don't Do This

```rust
// ❌ Using unwrap in production code
let value = risky_operation().unwrap();

// ❌ Ignoring errors
let _ = might_fail();

// ❌ Generic error messages
return Err("Something went wrong".into());

// ❌ Mixing error handling approaches
fn mixed_errors() -> Result<(), Box<dyn std::error::Error>> {
    // Inconsistent error handling
}

// ❌ Not providing context
let data = load_file(path)?; // No context about which file failed
```

### ✅ Do This Instead

```rust
// ✅ Proper error handling with context
let value = risky_operation()
    .context("Failed to perform risky operation")?;

// ✅ Handle or propagate errors explicitly
if let Err(e) = might_fail() {
    eprintln!("Operation failed: {}", e);
    return Err(e);
}

// ✅ Specific error messages
return Err(MyError::InvalidInput {
    field: "email".to_string(),
    value: input.to_string(),
});

// ✅ Consistent error handling approach
fn consistent_errors() -> Result<(), MyAppError> {
    // Consistent with project patterns
}

// ✅ Rich context for debugging
let data = load_file(path)
    .with_context(|| format!("Failed to load config file: {}", path))?;
```

This error handling strategy ensures robust, maintainable error management across your Rust project while following industry best practices.

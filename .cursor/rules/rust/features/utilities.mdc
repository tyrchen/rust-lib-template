---
description:
globs:
alwaysApply: false
---
# 🛠️ UTILITY LIBRARIES BEST PRACTICES

> **TL;DR:** Essential utility patterns for authentication, CLI tools, data structures, and common development tasks.

## 🔍 UTILITY LIBRARY SELECTION STRATEGY

```mermaid
graph TD
    Start["Utility Requirements"] --> UtilityType{"Utility<br>Category?"}

    UtilityType -->|Authentication| AuthUtils["Authentication Utilities"]
    UtilityType -->|CLI Tools| CLIUtils["CLI Utilities"]
    UtilityType -->|Data Structures| DataUtils["Data Structure Utilities"]
    UtilityType -->|Validation| ValidationUtils["Validation Utilities"]

    AuthUtils --> JWT["JWT Token Management"]
    AuthUtils --> PasswordHash["Password Hashing"]

    CLIUtils --> ClapCLI["Clap CLI Framework"]
    CLIUtils --> ProgressBars["Progress Indicators"]

    DataUtils --> TypedBuilder["TypedBuilder Pattern"]
    DataUtils --> EnumDispatch["enum_dispatch"]

    ValidationUtils --> SerdeValidation["Serde Validation"]
    ValidationUtils --> CustomValidation["Custom Validators"]

    JWT --> Security["Security Implementation"]
    PasswordHash --> Security
    ClapCLI --> UserInterface["User Interface"]
    ProgressBars --> UserInterface
    TypedBuilder --> CodeGeneration["Code Generation"]
    EnumDispatch --> CodeGeneration
    SerdeValidation --> DataIntegrity["Data Integrity"]
    CustomValidation --> DataIntegrity

    Security --> Production["Production Utilities"]
    UserInterface --> Production
    CodeGeneration --> Production
    DataIntegrity --> Production

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style AuthUtils fill:#4dbb5f,stroke:#36873f,color:white
    style CLIUtils fill:#ffa64d,stroke:#cc7a30,color:white
    style DataUtils fill:#d94dbb,stroke:#a3378a,color:white
```

## 🔐 AUTHENTICATION AND SECURITY

### JWT with jsonwebtoken
```toml
# Cargo.toml - JWT configuration
[dependencies]
jsonwebtoken = "9.0"
serde = { version = "1.0", features = ["derive"] }
chrono = { version = "0.4", features = ["serde"] }
```

```rust
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub exp: i64,           // Expiration time
    pub iat: i64,           // Issued at
    pub user_role: String,  // Custom claim
    pub session_id: String, // Session identifier
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_token_expiry: i64,  // seconds
    refresh_token_expiry: i64, // seconds
}

impl JwtService {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            access_token_expiry: 3600,      // 1 hour
            refresh_token_expiry: 604800,   // 7 days
        }
    }

    pub fn generate_token_pair(&self, user_id: &str, role: &str) -> Result<TokenPair, JwtError> {
        let now = Utc::now().timestamp();
        let session_id = uuid::Uuid::new_v4().to_string();

        // Access token
        let access_claims = Claims {
            sub: user_id.to_string(),
            exp: now + self.access_token_expiry,
            iat: now,
            user_role: role.to_string(),
            session_id: session_id.clone(),
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)?;

        // Refresh token (longer expiry, minimal claims)
        let refresh_claims = Claims {
            sub: user_id.to_string(),
            exp: now + self.refresh_token_expiry,
            iat: now,
            user_role: "refresh".to_string(),
            session_id,
        };

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.access_token_expiry,
        })
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    pub fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, JwtError> {
        let claims = self.validate_token(refresh_token)?;

        // Verify it's a refresh token
        if claims.user_role != "refresh" {
            return Err(JwtError::InvalidTokenType);
        }

        // Generate new token pair
        self.generate_token_pair(&claims.sub, "user") // Default role, should be fetched from DB
    }
}

#[derive(thiserror::Error, Debug)]
pub enum JwtError {
    #[error("JWT encoding/decoding error: {0}")]
    Token(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid token type")]
    InvalidTokenType,
    #[error("Token expired")]
    Expired,
}
```

## 🖥️ COMMAND LINE INTERFACES

### CLI with clap
```toml
# Cargo.toml - CLI configuration
[dependencies]
clap = { version = "4.0", features = ["derive"] }
anyhow = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
```

```rust
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "myapp")]
#[command(about = "A comprehensive application with multiple commands")]
#[command(version)]
pub struct Cli {
    /// Global configuration file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// User management commands
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Server operations
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Database operations
    Database {
        #[command(subcommand)]
        action: DatabaseAction,
    },
}

#[derive(Subcommand)]
pub enum UserAction {
    /// Create a new user
    Create {
        /// Username
        #[arg(short, long)]
        username: String,
        /// Email address
        #[arg(short, long)]
        email: String,
        /// User role
        #[arg(short, long, value_enum, default_value_t = UserRole::User)]
        role: UserRole,
    },
    /// List all users
    List {
        /// Maximum number of users to display
        #[arg(short, long, default_value_t = 50)]
        limit: usize,
        /// Filter by role
        #[arg(short, long)]
        role: Option<UserRole>,
    },
    /// Delete a user
    Delete {
        /// User ID or username
        #[arg(short, long)]
        identifier: String,
        /// Force deletion without confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ServerAction {
    /// Start the server
    Start {
        /// Port to bind to
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        /// Host to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },
    /// Stop the server
    Stop,
    /// Show server status
    Status,
}

#[derive(Subcommand)]
pub enum DatabaseAction {
    /// Run database migrations
    Migrate {
        /// Migration direction
        #[arg(value_enum, default_value_t = MigrationDirection::Up)]
        direction: MigrationDirection,
    },
    /// Seed the database with test data
    Seed {
        /// Environment to seed
        #[arg(short, long, default_value = "development")]
        env: String,
    },
    /// Reset the database
    Reset {
        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(ValueEnum, Clone)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
}

#[derive(ValueEnum, Clone)]
pub enum UserRole {
    Admin,
    User,
    Guest,
}

#[derive(ValueEnum, Clone)]
pub enum MigrationDirection {
    Up,
    Down,
}

// CLI execution logic
pub async fn run_cli() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    std::env::set_var("RUST_LOG", log_level);
    tracing_subscriber::fmt::init();

    match cli.command {
        Commands::User { action } => handle_user_command(action, cli.format).await,
        Commands::Server { action } => handle_server_command(action, cli.format).await,
        Commands::Database { action } => handle_database_command(action, cli.format).await,
    }
}

async fn handle_user_command(action: UserAction, format: OutputFormat) -> anyhow::Result<()> {
    match action {
        UserAction::Create { username, email, role } => {
            println!("Creating user: {} ({}) with role: {:?}", username, email, role);
            // Implementation
        }
        UserAction::List { limit, role } => {
            println!("Listing up to {} users", limit);
            if let Some(role) = role {
                println!("Filtering by role: {:?}", role);
            }
            // Implementation
        }
        UserAction::Delete { identifier, force } => {
            if !force {
                println!("Are you sure you want to delete user '{}'? [y/N]", identifier);
                // Confirmation logic
            }
            // Implementation
        }
    }
    Ok(())
}
```

## 🏗️ BUILDER PATTERNS

### Typed Builder
```toml
# Cargo.toml - Builder configuration
[dependencies]
typed-builder = "0.21"
serde = { version = "1.0", features = ["derive"] }
```

```rust
use typed_builder::TypedBuilder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, TypedBuilder, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserConfig {
    /// Required: User's email address
    pub email: String,

    /// Required: Username
    pub username: String,

    /// Optional: Display name (defaults to username)
    #[builder(default = self.username.clone())]
    pub display_name: String,

    /// Optional: User role
    #[builder(default = UserRole::User)]
    pub role: UserRole,

    /// Optional: Whether user is active
    #[builder(default = true)]
    pub is_active: bool,

    /// Optional: User preferences
    #[builder(default)]
    pub preferences: UserPreferences,

    /// Optional: Profile image URL
    #[builder(default, setter(strip_option))]
    pub avatar_url: Option<String>,

    /// Optional: User tags (for organization)
    #[builder(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, TypedBuilder, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPreferences {
    #[builder(default = String::from("en"))]
    pub language: String,

    #[builder(default = String::from("UTC"))]
    pub timezone: String,

    #[builder(default = true)]
    pub email_notifications: bool,

    #[builder(default = false)]
    pub dark_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
    Guest,
}

impl Default for UserRole {
    fn default() -> Self {
        Self::User
    }
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            language: "en".to_string(),
            timezone: "UTC".to_string(),
            email_notifications: true,
            dark_mode: false,
        }
    }
}

// Usage examples
pub fn create_user_examples() {
    // Minimal required fields
    let user1 = UserConfig::builder()
        .email("john@example.com".to_string())
        .username("john_doe".to_string())
        .build();

    // Full configuration
    let user2 = UserConfig::builder()
        .email("admin@example.com".to_string())
        .username("admin".to_string())
        .display_name("System Administrator".to_string())
        .role(UserRole::Admin)
        .is_active(true)
        .avatar_url("https://example.com/avatar.jpg".to_string())
        .tags(vec!["admin".to_string(), "system".to_string()])
        .preferences(
            UserPreferences::builder()
                .language("en".to_string())
                .timezone("America/New_York".to_string())
                .email_notifications(false)
                .dark_mode(true)
                .build()
        )
        .build();

    println!("User 1: {:?}", user1);
    println!("User 2: {:?}", user2);
}
```

## 🧮 RANDOM GENERATION AND UTILITIES

### Random Data Generation
```toml
# Cargo.toml - Random utilities
[dependencies]
rand = "0.8"
getrandom = "0.3"
uuid = { version = "1.17", features = ["v4", "serde"] }
base64 = "0.22"
```

```rust
use rand::{Rng, thread_rng, distributions::Alphanumeric};
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};

pub struct RandomGenerator;

impl RandomGenerator {
    /// Generate a secure random string for API keys, tokens, etc.
    pub fn secure_string(length: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    /// Generate a UUID v4
    pub fn uuid() -> String {
        Uuid::new_v4().to_string()
    }

    /// Generate a short ID (URL-safe)
    pub fn short_id() -> String {
        let uuid_bytes = Uuid::new_v4().as_bytes();
        general_purpose::URL_SAFE_NO_PAD.encode(&uuid_bytes[..8])
    }

    /// Generate a random integer within range
    pub fn int_range(min: i32, max: i32) -> i32 {
        thread_rng().gen_range(min..=max)
    }

    /// Generate random bytes
    pub fn bytes(length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
        bytes
    }

    /// Generate a base64-encoded random string
    pub fn base64_string(byte_length: usize) -> String {
        let bytes = Self::bytes(byte_length);
        general_purpose::STANDARD.encode(&bytes)
    }

    /// Generate a session ID
    pub fn session_id() -> String {
        format!("sess_{}", Self::secure_string(32))
    }

    /// Generate a API key
    pub fn api_key() -> String {
        format!("ak_{}", Self::base64_string(24))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_length() {
        let str32 = RandomGenerator::secure_string(32);
        assert_eq!(str32.len(), 32);

        let str64 = RandomGenerator::secure_string(64);
        assert_eq!(str64.len(), 64);
    }

    #[test]
    fn test_uuid_format() {
        let uuid = RandomGenerator::uuid();
        assert!(Uuid::parse_str(&uuid).is_ok());
    }

    #[test]
    fn test_short_id_uniqueness() {
        let id1 = RandomGenerator::short_id();
        let id2 = RandomGenerator::short_id();
        assert_ne!(id1, id2);
        assert!(id1.len() > 0);
    }

    #[test]
    fn test_int_range() {
        for _ in 0..100 {
            let val = RandomGenerator::int_range(1, 10);
            assert!(val >= 1 && val <= 10);
        }
    }
}
```

## 📊 ENHANCED DERIVE MACROS

### Using derive_more
```toml
# Cargo.toml - Enhanced derives
[dependencies]
derive_more = { version = "2", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

```rust
use derive_more::{Display, Error, From, Into, Constructor, Deref, DerefMut};
use serde::{Deserialize, Serialize};

// Custom string wrapper with validation
#[derive(Debug, Clone, Display, From, Into, Deref, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct EmailAddress(String);

impl TryFrom<String> for EmailAddress {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.contains('@') && value.len() > 5 {
            Ok(EmailAddress(value))
        } else {
            Err(ValidationError::InvalidEmail)
        }
    }
}

// Enhanced error types
#[derive(Debug, Display, Error)]
pub enum ServiceError {
    #[display(fmt = "User not found: {}", user_id)]
    UserNotFound { user_id: String },

    #[display(fmt = "Database error: {}", source)]
    Database {
        #[error(source)]
        source: sqlx::Error
    },

    #[display(fmt = "Validation failed: {}", field)]
    Validation { field: String },

    #[display(fmt = "Authentication failed")]
    Authentication,
}

#[derive(Debug, Display, Error)]
pub enum ValidationError {
    #[display(fmt = "Invalid email format")]
    InvalidEmail,

    #[display(fmt = "Field '{}' is required", field)]
    Required { field: String },

    #[display(fmt = "Value '{}' is too long (max: {})", value, max)]
    TooLong { value: String, max: usize },
}

// Constructor patterns
#[derive(Debug, Clone, Constructor, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSession {
    pub user_id: String,
    pub session_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[new(default)]
    pub is_active: bool,
}

// Wrapper types with automatic conversions
#[derive(Debug, Clone, From, Into, Deref, DerefMut, Serialize, Deserialize)]
pub struct UserId(String);

#[derive(Debug, Clone, From, Into, Deref, DerefMut, Serialize, Deserialize)]
pub struct SessionToken(String);

impl UserId {
    pub fn new() -> Self {
        Self(RandomGenerator::uuid())
    }
}

impl SessionToken {
    pub fn new() -> Self {
        Self(RandomGenerator::session_id())
    }
}

// Usage examples
pub fn demonstrate_enhanced_types() -> Result<(), Box<dyn std::error::Error>> {
    // Email validation
    let email = EmailAddress::try_from("user@example.com".to_string())?;
    println!("Valid email: {}", email);

    // Constructor usage
    let session = UserSession::new(
        "user_123".to_string(),
        "sess_abc".to_string(),
        chrono::Utc::now(),
        chrono::Utc::now() + chrono::Duration::hours(24),
    );
    println!("Session: {:?}", session);

    // Wrapper types
    let user_id = UserId::new();
    let token = SessionToken::new();
    println!("User ID: {}, Token: {}", *user_id, *token);

    Ok(())
}
```

## 🚨 UTILITIES ANTI-PATTERNS

### What to Avoid
```rust
// ❌ Don't use outdated JWT libraries
// use frank_jwt;  // Use jsonwebtoken instead

// ❌ Don't use structopt (deprecated)
// use structopt::StructOpt;  // Use clap with derive instead

// ❌ Don't manually implement builders
// pub struct ConfigBuilder {
//     field1: Option<String>,
//     field2: Option<i32>,
// }  // Use typed-builder instead

// ❌ Don't use thread_rng() for cryptographic purposes
// let password = thread_rng().gen::<u64>().to_string();  // Use getrandom for security

// ❌ Don't ignore JWT validation
// let claims = decode::<Claims>(token, key, &Validation::default());  // Configure properly
```

## ✅ UTILITIES CHECKLIST

```markdown
### Utilities Implementation Verification
- [ ] JWT authentication with proper validation and expiry
- [ ] CLI with comprehensive subcommands and help text
- [ ] Builder patterns using typed-builder
- [ ] Enhanced error types with derive_more
- [ ] Secure random generation for sensitive data
- [ ] Proper validation for wrapper types
- [ ] Constructor patterns for complex types
- [ ] Base64 encoding for binary data
- [ ] UUID generation for identifiers
- [ ] Comprehensive error handling
- [ ] Input validation and sanitization
- [ ] Type safety with wrapper types
```

This utilities standard provides robust patterns for common development tasks while maintaining type safety and security best practices.

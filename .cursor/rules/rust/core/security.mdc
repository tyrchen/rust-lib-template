---
description:
globs:
alwaysApply: false
---
# 🔐 RUST SECURITY BEST PRACTICES

> **TL;DR:** Security-focused programming patterns for Rust applications, covering input validation, cryptography, secrets management, and secure coding practices.

## 🔍 SECURITY IMPLEMENTATION STRATEGY

```mermaid
graph TD
    Start["Security Assessment"] --> ThreatModel["Threat Modeling"]

    ThreatModel --> InputSecurity{"Input<br>Validation?"}
    ThreatModel --> AuthSecurity{"Authentication<br>Required?"}
    ThreatModel --> DataSecurity{"Data<br>Protection?"}
    ThreatModel --> AccessSecurity{"Access<br>Control?"}

    InputSecurity -->|Yes| Validation["Input Validation"]
    InputSecurity -->|No| InputDone["✓"]

    AuthSecurity -->|Yes| PasswordHash["Password Hashing"]
    AuthSecurity -->|No| AuthDone["✓"]

    DataSecurity -->|Yes| Encryption["Data Encryption"]
    DataSecurity -->|No| DataDone["✓"]

    AccessSecurity -->|Yes| RBAC["Role-Based Access Control"]
    AccessSecurity -->|No| AccessDone["✓"]

    Validation --> PathTraversal["Path Traversal Prevention"]
    PathTraversal --> SQLInjection["SQL Injection Prevention"]

    PasswordHash --> Argon2["Argon2 Implementation"]
    Argon2 --> JWT["JWT Token Security"]

    Encryption --> SecretsManagement["Secrets Management"]
    SecretsManagement --> AESGCMEncryption["AES-GCM Encryption"]

    RBAC --> RateLimiting["Rate Limiting"]
    RateLimiting --> Audit["Security Audit Logging"]

    SQLInjection --> SecurityDone["Security Verified"]
    JWT --> SecurityDone
    AESGCMEncryption --> SecurityDone
    Audit --> SecurityDone
    InputDone --> SecurityDone
    AuthDone --> SecurityDone
    DataDone --> SecurityDone
    AccessDone --> SecurityDone

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style ThreatModel fill:#ffa64d,stroke:#cc7a30,color:white
    style Argon2 fill:#4dbb5f,stroke:#36873f,color:white
    style SecurityDone fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 SECURITY PRINCIPLES

### Input Validation and Sanitization
```rust
use validator::{Validate, ValidationError};
use regex::Regex;
use std::collections::HashSet;

// ✅ Always validate and sanitize user input
#[derive(Debug, Clone, Validate)]
pub struct UserRegistration {
    #[validate(email, message = "Invalid email format")]
    pub email: String,

    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    #[validate(custom = "validate_password_strength")]
    pub password: String,

    #[validate(length(min = 2, max = 50, message = "Username must be 2-50 characters"))]
    #[validate(regex = "USERNAME_REGEX", message = "Username contains invalid characters")]
    pub username: String,
}

lazy_static::lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    static ref FORBIDDEN_PASSWORDS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("password");
        set.insert("123456");
        set.insert("admin");
        set.insert("qwerty");
        set
    };
}

fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    // Check for forbidden passwords
    if FORBIDDEN_PASSWORDS.contains(&password.to_lowercase().as_str()) {
        return Err(ValidationError::new("forbidden_password"));
    }

    // Require at least one uppercase, lowercase, digit, and special character
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

    if !(has_upper && has_lower && has_digit && has_special) {
        return Err(ValidationError::new("weak_password"));
    }

    Ok(())
}

// ✅ SQL injection prevention with parameterized queries
pub async fn find_user_by_email(
    pool: &sqlx::PgPool,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    // ✅ Safe: Uses parameterized query
    sqlx::query_as::<_, User>(
        "SELECT id, email, username FROM users WHERE email = $1"
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

// ❌ NEVER: String interpolation vulnerable to SQL injection
// let query = format!("SELECT * FROM users WHERE email = '{}'", email);
```

### Path Traversal Prevention
```rust
use std::path::{Path, PathBuf};

// ✅ Safe file path handling
pub fn safe_file_access(base_dir: &Path, user_path: &str) -> Result<PathBuf, SecurityError> {
    // Normalize and resolve the path
    let requested_path = base_dir.join(user_path);
    let canonical_path = requested_path.canonicalize()
        .map_err(|_| SecurityError::InvalidPath)?;

    // Ensure the canonical path is within the base directory
    if !canonical_path.starts_with(base_dir) {
        return Err(SecurityError::PathTraversal);
    }

    Ok(canonical_path)
}

// ✅ File upload with validation
pub async fn upload_file(
    file_data: &[u8],
    filename: &str,
    upload_dir: &Path,
) -> Result<PathBuf, SecurityError> {
    // Validate filename
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(SecurityError::InvalidFilename);
    }

    // Check file size
    const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10MB
    if file_data.len() > MAX_FILE_SIZE {
        return Err(SecurityError::FileTooLarge);
    }

    // Validate file type by magic bytes
    let file_type = detect_file_type(file_data)?;
    if !is_allowed_file_type(&file_type) {
        return Err(SecurityError::DisallowedFileType);
    }

    // Generate safe filename
    let safe_filename = sanitize_filename(filename);
    let file_path = upload_dir.join(safe_filename);

    tokio::fs::write(&file_path, file_data).await
        .map_err(|_| SecurityError::FileWriteError)?;

    Ok(file_path)
}

fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect()
}
```

## 🔑 CRYPTOGRAPHY AND HASHING

### Password Hashing with Argon2
```rust
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};

// ✅ Secure password hashing with Argon2 (recommended)
pub struct PasswordService;

impl PasswordService {
    pub fn hash_password(password: &str) -> Result<String, SecurityError> {
        let salt = SaltString::generate(&mut OsRng);

        // Use Argon2id (default) with recommended parameters
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| SecurityError::HashingError)?;

        Ok(password_hash.to_string())
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, SecurityError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|_| SecurityError::InvalidHash)?;

        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    // ✅ Custom Argon2 configuration for high-security applications
    pub fn hash_password_high_security(password: &str) -> Result<String, SecurityError> {
        use argon2::{Algorithm, Params, Version};

        let salt = SaltString::generate(&mut OsRng);

        // Custom parameters for higher security (adjust based on performance requirements)
        let params = Params::new(
            65536,  // m_cost (memory cost) - 64 MB
            3,      // t_cost (time cost) - 3 iterations
            4,      // p_cost (parallelism) - 4 threads
            Some(32) // output length
        ).map_err(|_| SecurityError::HashingError)?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| SecurityError::HashingError)?;

        Ok(password_hash.to_string())
    }
}
```

### JWT Token Security
```rust
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // Subject (user ID)
    pub exp: i64,         // Expiration time
    pub iat: i64,         // Issued at
    pub jti: String,      // JWT ID for revocation
    pub scope: Vec<String>, // User permissions
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

impl JwtService {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            algorithm: Algorithm::HS256,
        }
    }

    pub fn create_token(&self, user_id: &str, scopes: Vec<String>) -> Result<String, SecurityError> {
        let now = Utc::now();
        let expiration = now + Duration::hours(24);

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration.timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            scope: scopes,
        };

        let mut header = Header::new(self.algorithm);
        header.kid = Some("1".to_string()); // Key ID for key rotation

        encode(&header, &claims, &self.encoding_key)
            .map_err(|_| SecurityError::TokenCreationError)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, SecurityError> {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| SecurityError::InvalidToken)?;

        Ok(token_data.claims)
    }
}
```

## 🔒 SECRETS MANAGEMENT

### Environment Variable Security
```rust
use std::env;
use zeroize::Zeroize;

// ✅ Secure secret handling
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Secret {
    value: String,
}

impl Secret {
    pub fn from_env(key: &str) -> Result<Self, SecurityError> {
        let value = env::var(key)
            .map_err(|_| SecurityError::MissingSecret)?;

        if value.is_empty() {
            return Err(SecurityError::EmptySecret);
        }

        Ok(Self { value })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    // ❌ Never implement Display or Debug for secrets
    // This prevents accidental logging
}

// ✅ Configuration with secure defaults
#[derive(Debug)]
pub struct SecurityConfig {
    pub jwt_secret: Secret,
    pub database_url: Secret,
    pub encryption_key: Secret,
    pub session_timeout: Duration,
    pub max_login_attempts: u32,
    pub rate_limit_per_minute: u32,
}

impl SecurityConfig {
    pub fn from_env() -> Result<Self, SecurityError> {
        Ok(Self {
            jwt_secret: Secret::from_env("JWT_SECRET")?,
            database_url: Secret::from_env("DATABASE_URL")?,
            encryption_key: Secret::from_env("ENCRYPTION_KEY")?,
            session_timeout: Duration::minutes(
                env::var("SESSION_TIMEOUT_MINUTES")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()
                    .unwrap_or(30)
            ),
            max_login_attempts: env::var("MAX_LOGIN_ATTEMPTS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
            rate_limit_per_minute: env::var("RATE_LIMIT_PER_MINUTE")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
        })
    }
}
```

### Data Encryption
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};
use rand::{RngCore, rngs::OsRng};

pub struct EncryptionService {
    cipher: Aes256Gcm,
}

impl EncryptionService {
    pub fn new(key: &[u8]) -> Result<Self, SecurityError> {
        if key.len() != 32 {
            return Err(SecurityError::InvalidKeyLength);
        }

        let key = Key::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecurityError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SecurityError::EncryptionError)?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.append(&mut ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if encrypted_data.len() < 12 {
            return Err(SecurityError::InvalidCiphertext);
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| SecurityError::DecryptionError)
    }
}

// ✅ Secure data structure for sensitive information
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SensitiveData {
    data: Vec<u8>,
}

impl SensitiveData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}
```

## 🛡️ ACCESS CONTROL AND AUTHORIZATION

### Role-Based Access Control (RBAC)
```rust
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Permission {
    UserRead,
    UserWrite,
    UserDelete,
    AdminAccess,
    SystemConfig,
}

#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub permissions: HashSet<Permission>,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub roles: HashSet<String>,
}

pub struct AuthorizationService {
    roles: HashMap<String, Role>,
    user_sessions: HashMap<String, User>,
}

impl AuthorizationService {
    pub fn new() -> Self {
        let mut roles = HashMap::new();

        // Define standard roles
        roles.insert("user".to_string(), Role {
            name: "user".to_string(),
            permissions: [Permission::UserRead].into_iter().collect(),
        });

        roles.insert("admin".to_string(), Role {
            name: "admin".to_string(),
            permissions: [
                Permission::UserRead,
                Permission::UserWrite,
                Permission::UserDelete,
                Permission::AdminAccess,
            ].into_iter().collect(),
        });

        roles.insert("super_admin".to_string(), Role {
            name: "super_admin".to_string(),
            permissions: [
                Permission::UserRead,
                Permission::UserWrite,
                Permission::UserDelete,
                Permission::AdminAccess,
                Permission::SystemConfig,
            ].into_iter().collect(),
        });

        Self {
            roles,
            user_sessions: HashMap::new(),
        }
    }

    pub fn check_permission(&self, user_id: &str, permission: &Permission) -> bool {
        if let Some(user) = self.user_sessions.get(user_id) {
            for role_name in &user.roles {
                if let Some(role) = self.roles.get(role_name) {
                    if role.permissions.contains(permission) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn require_permission(&self, user_id: &str, permission: Permission) -> Result<(), SecurityError> {
        if self.check_permission(user_id, &permission) {
            Ok(())
        } else {
            Err(SecurityError::InsufficientPermissions)
        }
    }
}

// ✅ Authorization middleware for web frameworks
pub async fn require_auth_middleware(
    auth_service: &AuthorizationService,
    user_id: &str,
    required_permission: Permission,
) -> Result<(), SecurityError> {
    auth_service.require_permission(user_id, required_permission)
}
```

## 🚨 RATE LIMITING AND DDOS PROTECTION

### Rate Limiting Implementation
```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct RateLimiter {
    limits: RwLock<HashMap<String, RateLimit>>,
    max_requests: u32,
    window_duration: Duration,
}

#[derive(Debug)]
struct RateLimit {
    requests: Vec<Instant>,
    last_cleanup: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            limits: RwLock::new(HashMap::new()),
            max_requests,
            window_duration,
        }
    }

    pub async fn check_rate_limit(&self, identifier: &str) -> Result<(), SecurityError> {
        let now = Instant::now();
        let mut limits = self.limits.write().await;

        let rate_limit = limits.entry(identifier.to_string()).or_insert(RateLimit {
            requests: Vec::new(),
            last_cleanup: now,
        });

        // Cleanup old requests
        if now.duration_since(rate_limit.last_cleanup) > self.window_duration {
            rate_limit.requests.retain(|&request_time| {
                now.duration_since(request_time) <= self.window_duration
            });
            rate_limit.last_cleanup = now;
        }

        // Check if limit exceeded
        if rate_limit.requests.len() >= self.max_requests as usize {
            return Err(SecurityError::RateLimitExceeded);
        }

        // Add current request
        rate_limit.requests.push(now);
        Ok(())
    }
}

// ✅ IP-based rate limiting for web endpoints
pub async fn rate_limit_by_ip(
    rate_limiter: &RateLimiter,
    ip_address: &str,
) -> Result<(), SecurityError> {
    rate_limiter.check_rate_limit(ip_address).await
}
```

## 🚨 SECURITY ERROR TYPES

### Comprehensive Security Errors
```rust
#[derive(thiserror::Error, Debug)]
pub enum SecurityError {
    #[error("Invalid email format")]
    InvalidEmail,

    #[error("Weak password")]
    WeakPassword,

    #[error("Path traversal attempt detected")]
    PathTraversal,

    #[error("Invalid file path")]
    InvalidPath,

    #[error("Invalid filename")]
    InvalidFilename,

    #[error("File too large")]
    FileTooLarge,

    #[error("Disallowed file type")]
    DisallowedFileType,

    #[error("File write error")]
    FileWriteError,

    #[error("Hashing error")]
    HashingError,

    #[error("Password verification error")]
    VerificationError,

    #[error("Invalid hash format")]
    InvalidHash,

    #[error("Token creation error")]
    TokenCreationError,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Missing secret configuration")]
    MissingSecret,

    #[error("Empty secret value")]
    EmptySecret,

    #[error("Invalid encryption key length")]
    InvalidKeyLength,

    #[error("Encryption failed")]
    EncryptionError,

    #[error("Decryption failed")]
    DecryptionError,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Authentication required")]
    AuthenticationRequired,

    #[error("Session expired")]
    SessionExpired,

    #[error("Account locked")]
    AccountLocked,
}

impl SecurityError {
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidEmail
                | Self::WeakPassword
                | Self::PathTraversal
                | Self::InvalidPath
                | Self::InvalidFilename
                | Self::FileTooLarge
                | Self::DisallowedFileType
                | Self::InvalidToken
                | Self::InsufficientPermissions
                | Self::RateLimitExceeded
                | Self::AuthenticationRequired
        )
    }

    pub fn should_log_details(&self) -> bool {
        !self.is_client_error()
    }
}
```

## ✅ SECURITY CHECKLIST

```markdown
### Security Implementation Verification
- [ ] All user inputs are validated and sanitized
- [ ] SQL queries use parameterized statements
- [ ] File paths are validated against traversal attacks
- [ ] File uploads are validated by type and size
- [ ] Passwords are hashed with Argon2
- [ ] JWT tokens include expiration and proper validation
- [ ] Secrets are loaded from environment variables
- [ ] Sensitive data structures implement Zeroize
- [ ] Encryption uses authenticated encryption (AES-GCM)
- [ ] Role-based access control is implemented
- [ ] Rate limiting protects against abuse
- [ ] Error messages don't leak sensitive information
- [ ] Security headers are set in HTTP responses
- [ ] Input validation happens on both client and server
- [ ] Audit logging tracks security-relevant events
- [ ] Regular security updates are applied
- [ ] Cryptographic randomness uses secure sources
- [ ] Session management includes timeout and rotation
```

This security guide provides comprehensive protection patterns while maintaining usability and performance in Rust applications.

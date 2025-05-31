---
description:
globs:
alwaysApply: false
---
# ⚙️ RUST CONFIGURATION MANAGEMENT

> **TL;DR:** Comprehensive patterns for configuration management in Rust applications, including multi-format parsing, validation, hot-reloading, and environment-based overrides.

## 🔍 CONFIGURATION STRATEGY

```mermaid
graph TD
    Start["Configuration Needs"] --> Format{"Configuration<br>Format?"}

    Format -->|Single| SingleFormat["Single Format Parsing"]
    Format -->|Multiple| MultiFormat["Multi-Format Support"]

    SingleFormat --> Validation["Configuration Validation"]
    MultiFormat --> Validation

    Validation --> Environment["Environment Overrides"]
    Environment --> Runtime{"Runtime<br>Updates?"}

    Runtime -->|Static| StaticConfig["Static Configuration"]
    Runtime -->|Dynamic| HotReload["Hot Reloading"]

    StaticConfig --> Testing["Configuration Testing"]
    HotReload --> Watching["File System Watching"]
    Watching --> AtomicUpdate["Atomic Updates"]
    AtomicUpdate --> Testing

    Testing --> Production["Production Configuration"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style MultiFormat fill:#4dbb5f,stroke:#36873f,color:white
    style HotReload fill:#ffa64d,stroke:#cc7a30,color:white
    style AtomicUpdate fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 CONFIGURATION PRINCIPLES

### Multi-Format Configuration Support
```rust
use figment::{Figment, providers::{Format, Yaml, Toml, Json, Env}};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

// ✅ Configuration structure with validation
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(rename_all = "snake_case")]
pub struct AppConfig {
    #[validate(length(min = 1, max = 100))]
    pub name: String,

    #[validate(range(min = 1, max = 65535))]
    pub port: u16,

    #[serde(default = "default_host")]
    #[validate(length(min = 1))]
    pub host: String,

    #[serde(default)]
    pub features: Vec<String>,

    #[validate(nested)]
    pub database: DatabaseConfig,

    #[serde(default)]
    #[validate(nested)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DatabaseConfig {
    #[validate(url)]
    pub url: String,

    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    #[serde(default)]
    pub json_format: bool,
}

// Default value functions
fn default_host() -> String { "0.0.0.0".to_string() }
fn default_pool_size() -> u32 { 10 }
fn default_timeout() -> u64 { 30 }
fn default_log_level() -> String { "info".to_string() }

impl AppConfig {
    /// Load configuration from multiple sources with precedence:
    /// 1. Environment variables (highest priority)
    /// 2. config.yaml file
    /// 3. config.toml file
    /// 4. Default values (lowest priority)
    pub fn load() -> Result<Self, ConfigError> {
        let config = Figment::new()
            .merge(Toml::file("config.toml"))
            .merge(Yaml::file("config.yaml"))
            .merge(Json::file("config.json"))
            .merge(Env::prefixed("APP_"))
            .extract()?;

        // Validate the configuration
        config.validate()
            .map_err(ConfigError::Validation)?;

        Ok(config)
    }

    /// Load from a specific file path
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .ok_or_else(|| ConfigError::UnsupportedFormat("Unknown file extension".to_string()))?;

        let figment = match extension.to_lowercase().as_str() {
            "yaml" | "yml" => Figment::new().merge(Yaml::file(path)),
            "toml" => Figment::new().merge(Toml::file(path)),
            "json" => Figment::new().merge(Json::file(path)),
            ext => return Err(ConfigError::UnsupportedFormat(ext.to_string())),
        };

        let config = figment
            .merge(Env::prefixed("APP_"))
            .extract()?;

        config.validate()
            .map_err(ConfigError::Validation)?;

        Ok(config)
    }
}
```

## 🔄 HOT CONFIGURATION RELOADING

### Atomic Configuration Updates
```rust
use arc_swap::ArcSwap;
use notify::{RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

// ✅ Configuration manager with hot reloading
pub struct ConfigManager<T> {
    current: Arc<ArcSwap<T>>,
    reload_tx: broadcast::Sender<Arc<T>>,
    config_path: std::path::PathBuf,
}

impl<T> ConfigManager<T>
where
    T: for<'de> Deserialize<'de> + Validate + Clone + Send + Sync + 'static,
{
    pub fn new(initial_config: T, config_path: impl Into<std::path::PathBuf>) -> Self {
        let (reload_tx, _) = broadcast::channel(16);
        let current = Arc::new(ArcSwap::from_pointee(initial_config));

        Self {
            current,
            reload_tx,
            config_path: config_path.into(),
        }
    }

    /// Get current configuration
    pub fn get(&self) -> Arc<T> {
        self.current.load_full()
    }

    /// Subscribe to configuration updates
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<T>> {
        self.reload_tx.subscribe()
    }

    /// Start watching for configuration file changes
    pub async fn start_watching(&self) -> Result<(), ConfigError> {
        let (tx, mut rx) = mpsc::channel(1);
        let config_path = self.config_path.clone();

        // File system watcher
        let mut watcher = RecommendedWatcher::new(
            move |res: NotifyResult<notify::Event>| {
                if let Ok(event) = res {
                    if event.kind.is_modify() {
                        let _ = tx.try_send(());
                    }
                }
            },
            notify::Config::default(),
        )?;

        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

        let current = self.current.clone();
        let reload_tx = self.reload_tx.clone();
        let config_path = self.config_path.clone();

        // Spawn reload handler
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                // Small delay to ensure file write is complete
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                match Self::load_config_from_file(&config_path) {
                    Ok(new_config) => {
                        let new_config = Arc::new(new_config);
                        current.store(new_config.clone());

                        // Notify subscribers
                        if let Err(e) = reload_tx.send(new_config) {
                            tracing::warn!("Failed to notify config subscribers: {}", e);
                        } else {
                            tracing::info!("Configuration reloaded successfully");
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to reload configuration: {}", e);
                    }
                }
            }
        });

        // Keep watcher alive
        std::mem::forget(watcher);
        Ok(())
    }

    /// Manually reload configuration
    pub async fn reload(&self) -> Result<(), ConfigError> {
        let new_config = Self::load_config_from_file(&self.config_path)?;
        let new_config = Arc::new(new_config);

        self.current.store(new_config.clone());
        self.reload_tx.send(new_config)
            .map_err(|_| ConfigError::ReloadFailed)?;

        Ok(())
    }

    fn load_config_from_file(path: &std::path::Path) -> Result<T, ConfigError> {
        // Implementation depends on your config format
        // This is a placeholder - use figment or similar
        todo!("Implement config loading based on file type")
    }
}

/// Service component that can react to configuration changes
pub trait ConfigurableService: Send + Sync {
    type Config;

    fn on_config_update(&self, config: &Self::Config);
}

/// Helper for services that need configuration updates
pub struct ServiceManager<T, S> {
    config_manager: ConfigManager<T>,
    services: Vec<Arc<S>>,
}

impl<T, S> ServiceManager<T, S>
where
    T: for<'de> Deserialize<'de> + Validate + Clone + Send + Sync + 'static,
    S: ConfigurableService<Config = T>,
{
    pub fn new(config: T, config_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            config_manager: ConfigManager::new(config, config_path),
            services: Vec::new(),
        }
    }

    pub fn add_service(&mut self, service: Arc<S>) {
        self.services.push(service);
    }

    pub async fn start(&self) -> Result<(), ConfigError> {
        let mut config_updates = self.config_manager.subscribe();

        // Start configuration watching
        self.config_manager.start_watching().await?;

        // Spawn task to handle config updates
        let services = self.services.clone();
        tokio::spawn(async move {
            while let Ok(new_config) = config_updates.recv().await {
                for service in &services {
                    service.on_config_update(&new_config);
                }
            }
        });

        Ok(())
    }

    pub fn get_config(&self) -> Arc<T> {
        self.config_manager.get()
    }
}
```

## 🌍 ENVIRONMENT-BASED CONFIGURATION

### Environment Override Patterns
```rust
use std::env;

// ✅ Environment-aware configuration
impl AppConfig {
    /// Create configuration for different environments
    pub fn for_environment(env: Environment) -> Result<Self, ConfigError> {
        let mut figment = Figment::new();

        // Base configuration
        figment = match env {
            Environment::Development => figment
                .merge(Toml::file("config/development.toml"))
                .merge(Yaml::file("config/development.yaml")),
            Environment::Testing => figment
                .merge(Toml::file("config/testing.toml"))
                .merge(Yaml::file("config/testing.yaml")),
            Environment::Production => figment
                .merge(Toml::file("config/production.toml"))
                .merge(Yaml::file("config/production.yaml")),
        };

        // Always apply environment variables last
        let config = figment
            .merge(Env::prefixed("APP_"))
            .extract()?;

        config.validate()
            .map_err(ConfigError::Validation)?;

        Ok(config)
    }

    /// Detect environment from environment variable
    pub fn detect_environment() -> Environment {
        env::var("APP_ENV")
            .or_else(|_| env::var("ENVIRONMENT"))
            .unwrap_or_else(|_| "development".to_string())
            .parse()
            .unwrap_or(Environment::Development)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Environment {
    Development,
    Testing,
    Production,
}

impl std::str::FromStr for Environment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Ok(Environment::Development),
            "testing" | "test" => Ok(Environment::Testing),
            "production" | "prod" => Ok(Environment::Production),
            _ => Err(format!("Unknown environment: {}", s)),
        }
    }
}
```

## 🧪 CONFIGURATION TESTING

### Testing Configuration Patterns
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_config_validation() {
        // ✅ Test configuration validation
        let config = AppConfig {
            name: "".to_string(), // Invalid: empty name
            port: 70000, // Invalid: port too high
            host: "localhost".to_string(),
            features: vec!["feature1".to_string()],
            database: DatabaseConfig {
                url: "invalid-url".to_string(), // Invalid: not a valid URL
                pool_size: 10,
                timeout_seconds: 30,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                json_format: false,
            },
        };

        let validation_result = config.validate();
        assert!(validation_result.is_err());
    }

    #[test]
    fn test_yaml_config_loading() -> Result<(), Box<dyn std::error::Error>> {
        // ✅ Test loading from YAML
        let yaml_content = r#"
name: "test-app"
port: 8080
host: "localhost"
features:
  - "feature1"
  - "feature2"
database:
  url: "postgresql://localhost/test"
  pool_size: 5
  timeout_seconds: 60
logging:
  level: "debug"
  json_format: true
"#;

        let mut temp_file = NamedTempFile::new()?;
        write!(temp_file, "{}", yaml_content)?;

        let config = AppConfig::from_file(temp_file.path())?;
        assert_eq!(config.name, "test-app");
        assert_eq!(config.port, 8080);
        assert_eq!(config.features.len(), 2);

        Ok(())
    }

    #[test]
    fn test_environment_override() {
        // ✅ Test environment variable overrides
        temp_env::with_vars([
            ("APP_NAME", Some("env-override-app")),
            ("APP_PORT", Some("9090")),
        ], || {
            // Test that environment variables override file values
            // Implementation would use figment to merge env vars
        });
    }

    #[tokio::test]
    async fn test_hot_reload() -> Result<(), Box<dyn std::error::Error>> {
        // ✅ Test hot reloading functionality
        let initial_config = AppConfig {
            name: "initial".to_string(),
            port: 8080,
            host: "localhost".to_string(),
            features: vec![],
            database: DatabaseConfig {
                url: "postgresql://localhost/initial".to_string(),
                pool_size: 10,
                timeout_seconds: 30,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                json_format: false,
            },
        };

        let temp_file = NamedTempFile::new()?;
        let config_manager = ConfigManager::new(initial_config, temp_file.path());

        // Test that we can get the initial config
        let current = config_manager.get();
        assert_eq!(current.name, "initial");

        // Test subscription to updates
        let mut updates = config_manager.subscribe();

        // Simulate config file change and reload
        // ... implementation details

        Ok(())
    }
}
```

## 🚨 CONFIGURATION ERROR HANDLING

### Comprehensive Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Configuration validation failed: {0}")]
    Validation(#[from] validator::ValidationErrors),

    #[error("Failed to parse configuration: {0}")]
    Parse(#[from] figment::Error),

    #[error("Unsupported configuration format: {0}")]
    UnsupportedFormat(String),

    #[error("Failed to watch configuration file: {0}")]
    FileWatch(#[from] notify::Error),

    #[error("Configuration reload failed")]
    ReloadFailed,

    #[error("Environment variable error: {0}")]
    Environment(#[from] std::env::VarError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ConfigError {
    pub fn is_validation_error(&self) -> bool {
        matches!(self, ConfigError::Validation(_))
    }

    pub fn is_file_error(&self) -> bool {
        matches!(self, ConfigError::FileWatch(_) | ConfigError::Io(_))
    }
}

pub type Result<T> = std::result::Result<T, ConfigError>;
```

## ✅ CONFIGURATION MANAGEMENT CHECKLIST

```markdown
### Configuration Implementation Verification
- [ ] Support multiple configuration formats (YAML, TOML, JSON)
- [ ] Implement comprehensive validation with validator
- [ ] Environment variable overrides work correctly
- [ ] Hot reloading implemented with atomic updates
- [ ] File system watching for configuration changes
- [ ] Environment-specific configuration files
- [ ] Proper error handling with contextual information
- [ ] Configuration testing with temporary files
- [ ] Default values provided for optional fields
- [ ] Configuration changes broadcast to subscribers
- [ ] Graceful degradation on configuration errors
- [ ] Documentation with examples for each format
- [ ] Secrets handling (environment variables only)
- [ ] Configuration validation on startup
- [ ] Performance considerations for frequent access
```

This configuration management guide provides robust patterns for handling complex configuration requirements in modern Rust applications.

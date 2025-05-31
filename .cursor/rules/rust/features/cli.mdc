---
description:
globs:
alwaysApply: false
---
# 🖥️ RUST CLI APPLICATION STANDARDS

> **TL;DR:** Modern CLI application patterns using clap 4.0+ with derive features, subcommands, enum_dispatch, and production-ready command execution architecture.

## 🔍 CLI APPLICATION DESIGN STRATEGY

```mermaid
graph TD
    Start["CLI Application"] --> CLIType{"CLI<br>Complexity?"}

    CLIType -->|Simple| SimpleCLI["Single Command CLI"]
    CLIType -->|Complex| ComplexCLI["Multi-Command CLI"]

    SimpleCLI --> DirectExecution["Direct Execution"]
    ComplexCLI --> SubcommandArch["Subcommand Architecture"]

    SubcommandArch --> EnumDispatch["enum_dispatch Pattern"]
    EnumDispatch --> TraitExecution["CommandExecutor Trait"]

    DirectExecution --> ErrorHandling["Error Handling"]
    TraitExecution --> ErrorHandling

    ErrorHandling --> UserFeedback["User Feedback"]
    UserFeedback --> ProgressIndicators["Progress Indicators"]
    ProgressIndicators --> Configuration["Configuration Management"]

    Configuration --> Testing["CLI Testing"]
    Testing --> Documentation["Help & Documentation"]
    Documentation --> Completion["Shell Completion"]

    Completion --> Production["Production CLI"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style SimpleCLI fill:#4dbb5f,stroke:#36873f,color:white
    style ComplexCLI fill:#ffa64d,stroke:#cc7a30,color:white
    style EnumDispatch fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 CLI FRAMEWORK REQUIREMENTS

### Clap 4.0+ Configuration
- **Use clap 4.0+ with derive features** - Modern declarative CLI definition
- **Subcommand architecture** - Organized command structure for complex CLIs
- **enum_dispatch pattern** - Efficient command execution with trait dispatch
- **Comprehensive error handling** - User-friendly error messages and exit codes

## 📦 CLI DEPENDENCIES

```toml
# Cargo.toml - CLI application dependencies
[dependencies]
# CLI framework
clap = { version = "4.0", features = ["derive", "env", "unicode", "wrap_help"] }
enum_dispatch = "0.3"

# Error handling
anyhow = "1.0"
thiserror = "2.0"

# Async runtime (if needed)
tokio = { version = "1.45", features = ["macros", "rt-multi-thread", "fs", "process"] }

# Logging and tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json", "chrono"] }

# Configuration and environment
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"

# Utilities
colored = "2.0"                 # Terminal colors
indicatif = "0.17"             # Progress bars
dialoguer = "0.11"             # Interactive prompts
console = "0.15"               # Terminal utilities

# Optional: Advanced CLI features
clap_complete = "4.0"          # Shell completions
clap_mangen = "0.2"           # Manual page generation

[dev-dependencies]
assert_cmd = "2.0"             # CLI testing
predicates = "3.0"            # Assertion predicates
tempfile = "3.0"              # Temporary files for testing
```

## 🏗️ CLI APPLICATION ARCHITECTURE

```mermaid
graph TD
    CLI["CLI Entry Point"] --> Parser["Clap Parser"]
    Parser --> Args["Global Args"]
    Parser --> Commands["Subcommands"]

    Commands --> Dispatcher["enum_dispatch"]
    Dispatcher --> Executor["CommandExecutor Trait"]

    Executor --> Command1["DatabaseCommand"]
    Executor --> Command2["ServerCommand"]
    Executor --> Command3["MigrationCommand"]
    Executor --> Command4["ConfigCommand"]

    Command1 --> Result1["Command Result"]
    Command2 --> Result2["Command Result"]
    Command3 --> Result3["Command Result"]
    Command4 --> Result4["Command Result"]

    Args --> Config["Configuration"]
    Config --> Logger["Logging Setup"]

    style CLI fill:#4da6ff,stroke:#0066cc,color:white
    style Dispatcher fill:#4dbb5f,stroke:#36873f,color:white
    style Executor fill:#ffa64d,stroke:#cc7a30,color:white
    style Config fill:#d94dbb,stroke:#a3378a,color:white
```

## 🚀 CLI APPLICATION STRUCTURE

### Main CLI Entry Point

```rust
// src/main.rs
use anyhow::Result;
use tracing_subscriber::{fmt, EnvFilter};

mod cli;
mod commands;
mod config;
mod error;

use cli::{Args, Commands};
use commands::CommandExecutor;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    setup_logging()?;

    // Parse command line arguments
    let args = Args::parse();

    // Setup configuration
    let config = config::Config::load(&args.config)?;

    // Execute command
    match args.command.execute(&args, &config).await {
        Ok(()) => {
            tracing::info!("Command completed successfully");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Command failed: {}", e);
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn setup_logging() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(fmt::time::ChronoUtc::rfc_3339())
        .init();

    Ok(())
}
```

### CLI Arguments Definition

```rust
// src/cli.rs
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::commands::Commands;

/// A powerful CLI application for managing your project
#[derive(Debug, Parser)]
#[command(name = "mycli")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "A CLI tool with multiple commands")]
#[command(long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Args {
    /// Configuration file path
    #[arg(
        short = 'c',
        long = "config",
        value_name = "FILE",
        help = "Path to configuration file"
    )]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(
        short = 'v',
        long = "verbose",
        action = clap::ArgAction::Count,
        help = "Increase verbosity (-v, -vv, -vvv)"
    )]
    pub verbose: u8,

    /// Output format
    #[arg(
        long = "format",
        value_enum,
        default_value = "text",
        help = "Output format"
    )]
    pub format: OutputFormat,

    /// Disable colored output
    #[arg(
        long = "no-color",
        help = "Disable colored output"
    )]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
    Table,
}

impl Args {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    /// Get log level based on verbosity
    pub fn log_level(&self) -> tracing::Level {
        match self.verbose {
            0 => tracing::Level::WARN,
            1 => tracing::Level::INFO,
            2 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        }
    }
}
```

### Command Executor Trait and enum_dispatch

```rust
// src/commands/mod.rs
use anyhow::Result;
use async_trait::async_trait;
use clap::Subcommand;
use enum_dispatch::enum_dispatch;

use crate::{cli::Args, config::Config};

pub mod database;
pub mod server;
pub mod migration;
pub mod config_cmd;

pub use database::DatabaseCommand;
pub use server::ServerCommand;
pub use migration::MigrationCommand;
pub use config_cmd::ConfigCommand;

/// Command execution trait
#[async_trait]
#[enum_dispatch(Commands)]
pub trait CommandExecutor {
    async fn execute(&self, args: &Args, config: &Config) -> Result<()>;
}

/// All available commands with enum_dispatch
#[derive(Debug, Subcommand)]
#[enum_dispatch(CommandExecutor)]
pub enum Commands {
    /// Database management commands
    #[command(name = "db", alias = "database")]
    Database(DatabaseCommand),

    /// Server management commands
    #[command(name = "server", alias = "srv")]
    Server(ServerCommand),

    /// Database migration commands
    #[command(name = "migrate", alias = "migration")]
    Migration(MigrationCommand),

    /// Configuration management commands
    #[command(name = "config", alias = "cfg")]
    Config(ConfigCommand),
}
```

### Subcommand Implementation Examples

```rust
// src/commands/database.rs
use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::{Args, Subcommand};
use colored::*;

use crate::{cli::Args as GlobalArgs, config::Config, commands::CommandExecutor};

/// Database management commands
#[derive(Debug, Args)]
pub struct DatabaseCommand {
    #[command(subcommand)]
    pub action: DatabaseAction,
}

#[derive(Debug, Subcommand)]
pub enum DatabaseAction {
    /// Initialize database
    Init {
        /// Database URL override
        #[arg(long, env = "DATABASE_URL")]
        url: Option<String>,

        /// Force initialization (drop existing data)
        #[arg(long, short = 'f')]
        force: bool,
    },

    /// Check database connection
    Status {
        /// Show detailed status
        #[arg(long)]
        detailed: bool,
    },

    /// Backup database
    Backup {
        /// Output file path
        #[arg(short = 'o', long = "output")]
        output: std::path::PathBuf,

        /// Compression format
        #[arg(long, value_enum, default_value = "gzip")]
        compression: CompressionFormat,
    },

    /// Restore database from backup
    Restore {
        /// Input backup file
        #[arg(short = 'i', long = "input")]
        input: std::path::PathBuf,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum CompressionFormat {
    None,
    Gzip,
    Bzip2,
    Xz,
}

#[async_trait]
impl CommandExecutor for DatabaseCommand {
    async fn execute(&self, args: &GlobalArgs, config: &Config) -> Result<()> {
        tracing::info!("Executing database command: {:?}", self.action);

        match &self.action {
            DatabaseAction::Init { url, force } => {
                self.init_database(args, config, url.as_deref(), *force).await
            }
            DatabaseAction::Status { detailed } => {
                self.check_status(args, config, *detailed).await
            }
            DatabaseAction::Backup { output, compression } => {
                self.backup_database(args, config, output, compression).await
            }
            DatabaseAction::Restore { input, yes } => {
                self.restore_database(args, config, input, *yes).await
            }
        }
    }
}

impl DatabaseCommand {
    async fn init_database(
        &self,
        args: &GlobalArgs,
        config: &Config,
        url_override: Option<&str>,
        force: bool,
    ) -> Result<()> {
        let db_url = url_override
            .or(config.database.url.as_deref())
            .context("Database URL not configured")?;

        if force {
            println!("{}", "⚠️  Force initialization - this will drop all existing data!".yellow());

            if !self.confirm_action("Continue with force initialization?").await? {
                println!("{}", "Aborted by user".red());
                return Ok(());
            }
        }

        println!("{}", "🔧 Initializing database...".blue());

        // TODO: Implement actual database initialization
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        println!("{}", "✅ Database initialized successfully".green());
        Ok(())
    }

    async fn check_status(
        &self,
        args: &GlobalArgs,
        config: &Config,
        detailed: bool,
    ) -> Result<()> {
        println!("{}", "🔍 Checking database status...".blue());

        // TODO: Implement actual status check
        let status = "Connected";
        let version = "PostgreSQL 15.4";

        match args.format {
            crate::cli::OutputFormat::Json => {
                let status_obj = serde_json::json!({
                    "status": status,
                    "version": version,
                    "detailed": detailed
                });
                println!("{}", serde_json::to_string_pretty(&status_obj)?);
            }
            _ => {
                println!("Status: {}", status.green());
                println!("Version: {}", version);

                if detailed {
                    println!("Connection pool: 10/20");
                    println!("Active queries: 3");
                    println!("Last backup: 2024-01-15 10:30:00");
                }
            }
        }

        Ok(())
    }

    async fn backup_database(
        &self,
        args: &GlobalArgs,
        config: &Config,
        output: &std::path::Path,
        compression: &CompressionFormat,
    ) -> Result<()> {
        println!("{}", "💾 Creating database backup...".blue());

        // TODO: Implement actual backup logic
        use indicatif::{ProgressBar, ProgressStyle};

        let pb = ProgressBar::new(100);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        for i in 0..100 {
            pb.set_position(i + 1);
            pb.set_message(format!("Backing up table {}/50", i / 2 + 1));
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        pb.finish_with_message("Backup completed");
        println!("{} Backup saved to: {}", "✅".green(), output.display());

        Ok(())
    }

    async fn restore_database(
        &self,
        args: &GlobalArgs,
        config: &Config,
        input: &std::path::Path,
        skip_confirmation: bool,
    ) -> Result<()> {
        if !skip_confirmation {
            println!("{}", "⚠️  This will replace all existing data!".yellow());
            if !self.confirm_action("Continue with database restore?").await? {
                println!("{}", "Aborted by user".red());
                return Ok(());
            }
        }

        println!("{}", "🔄 Restoring database...".blue());

        // TODO: Implement actual restore logic
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        println!("{} Database restored from: {}", "✅".green(), input.display());
        Ok(())
    }

    async fn confirm_action(&self, message: &str) -> Result<bool> {
        use dialoguer::Confirm;

        Ok(Confirm::new()
            .with_prompt(message)
            .default(false)
            .interact()?)
    }
}
```

```rust
// src/commands/server.rs
use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::{Args, Subcommand};
use colored::*;
use std::net::SocketAddr;

use crate::{cli::Args as GlobalArgs, config::Config, commands::CommandExecutor};

/// Server management commands
#[derive(Debug, Args)]
pub struct ServerCommand {
    #[command(subcommand)]
    pub action: ServerAction,
}

#[derive(Debug, Subcommand)]
pub enum ServerAction {
    /// Start the server
    Start {
        /// Server bind address
        #[arg(long, short = 'a', default_value = "127.0.0.1:8080")]
        address: SocketAddr,

        /// Number of worker threads
        #[arg(long, short = 'w')]
        workers: Option<usize>,

        /// Run in development mode
        #[arg(long, short = 'd')]
        dev: bool,
    },

    /// Stop the server
    Stop {
        /// Process ID to stop
        #[arg(long, short = 'p')]
        pid: Option<u32>,

        /// Force stop (SIGKILL)
        #[arg(long, short = 'f')]
        force: bool,
    },

    /// Check server status
    Status {
        /// Server endpoint to check
        #[arg(long, default_value = "http://127.0.0.1:8080/health")]
        endpoint: String,

        /// Timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
    },

    /// Restart the server
    Restart {
        /// Graceful restart (zero downtime)
        #[arg(long)]
        graceful: bool,
    },
}

#[async_trait]
impl CommandExecutor for ServerCommand {
    async fn execute(&self, args: &GlobalArgs, config: &Config) -> Result<()> {
        tracing::info!("Executing server command: {:?}", self.action);

        match &self.action {
            ServerAction::Start { address, workers, dev } => {
                self.start_server(args, config, *address, *workers, *dev).await
            }
            ServerAction::Stop { pid, force } => {
                self.stop_server(args, config, *pid, *force).await
            }
            ServerAction::Status { endpoint, timeout } => {
                self.check_server_status(args, config, endpoint, *timeout).await
            }
            ServerAction::Restart { graceful } => {
                self.restart_server(args, config, *graceful).await
            }
        }
    }
}

impl ServerCommand {
    async fn start_server(
        &self,
        args: &GlobalArgs,
        config: &Config,
        address: SocketAddr,
        workers: Option<usize>,
        dev_mode: bool,
    ) -> Result<()> {
        println!("{}", "🚀 Starting server...".blue());

        let workers = workers.unwrap_or_else(num_cpus::get);

        if dev_mode {
            println!("{}", "🔧 Development mode enabled".yellow());
        }

        println!("Server address: {}", address.to_string().green());
        println!("Worker threads: {}", workers.to_string().green());

        // TODO: Implement actual server startup
        println!("{}", "✅ Server started successfully".green());
        println!("Press Ctrl+C to stop");

        // Simulate server running
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::select! {
            _ = ctrl_c => {
                println!("\n{}", "🛑 Received shutdown signal".yellow());
                println!("{}", "✅ Server stopped gracefully".green());
            }
        }

        Ok(())
    }

    async fn stop_server(
        &self,
        args: &GlobalArgs,
        config: &Config,
        pid: Option<u32>,
        force: bool,
    ) -> Result<()> {
        println!("{}", "🛑 Stopping server...".blue());

        if let Some(pid) = pid {
            println!("Stopping process with PID: {}", pid);
        }

        if force {
            println!("{}", "⚠️  Force stopping (SIGKILL)".yellow());
        } else {
            println!("{}", "Graceful shutdown (SIGTERM)".green());
        }

        // TODO: Implement actual server stop logic
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        println!("{}", "✅ Server stopped".green());
        Ok(())
    }

    async fn check_server_status(
        &self,
        args: &GlobalArgs,
        config: &Config,
        endpoint: &str,
        timeout: u64,
    ) -> Result<()> {
        println!("{} Checking server status: {}", "🔍".blue(), endpoint);

        // TODO: Implement actual health check
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .build()?;

        match client.get(endpoint).send().await {
            Ok(response) => {
                let status = response.status();
                match args.format {
                    crate::cli::OutputFormat::Json => {
                        let status_obj = serde_json::json!({
                            "endpoint": endpoint,
                            "status_code": status.as_u16(),
                            "status": "healthy"
                        });
                        println!("{}", serde_json::to_string_pretty(&status_obj)?);
                    }
                    _ => {
                        if status.is_success() {
                            println!("{} Server is healthy ({})", "✅".green(), status);
                        } else {
                            println!("{} Server returned error: {}", "❌".red(), status);
                        }
                    }
                }
            }
            Err(e) => {
                println!("{} Server is not responding: {}", "❌".red(), e);
                std::process::exit(1);
            }
        }

        Ok(())
    }

    async fn restart_server(
        &self,
        args: &GlobalArgs,
        config: &Config,
        graceful: bool,
    ) -> Result<()> {
        if graceful {
            println!("{}", "🔄 Performing graceful restart...".blue());
        } else {
            println!("{}", "🔄 Restarting server...".blue());
        }

        // TODO: Implement actual restart logic
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        println!("{}", "✅ Server restarted successfully".green());
        Ok(())
    }
}
```

## ⚙️ CONFIGURATION MANAGEMENT

```rust
// src/config.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub app: AppConfig,
    pub database: DatabaseConfig,
    pub server: ServerConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub name: String,
    pub version: String,
    pub environment: Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseConfig {
    pub url: Option<String>,
    pub max_connections: u32,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Staging,
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

impl Config {
    pub fn load(config_path: &Option<std::path::PathBuf>) -> Result<Self> {
        if let Some(path) = config_path {
            Self::load_from_file(path)
        } else {
            Self::load_default()
        }
    }

    fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => {
                serde_json::from_str(&content)
                    .with_context(|| "Failed to parse JSON config")
            }
            Some("yaml") | Some("yml") => {
                serde_yaml::from_str(&content)
                    .with_context(|| "Failed to parse YAML config")
            }
            _ => {
                anyhow::bail!("Unsupported config file format. Use .json or .yaml");
            }
        }
    }

    fn load_default() -> Result<Self> {
        Ok(Self {
            app: AppConfig {
                name: env!("CARGO_PKG_NAME").to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                environment: Environment::Development,
            },
            database: DatabaseConfig {
                url: std::env::var("DATABASE_URL").ok(),
                max_connections: 20,
                timeout_seconds: 30,
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                workers: None,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: LogFormat::Text,
            },
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::load_default().expect("Failed to create default config")
    }
}
```

## 🚨 ERROR HANDLING

```rust
// src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Command execution error: {0}")]
    Command(#[from] CommandError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Validation error: {0}")]
    Validation(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Config file not found: {path}")]
    NotFound { path: String },

    #[error("Invalid config format: {message}")]
    InvalidFormat { message: String },

    #[error("Missing required field: {field}")]
    MissingField { field: String },
}

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Invalid arguments: {message}")]
    InvalidArgs { message: String },

    #[error("Command failed: {message}")]
    ExecutionFailed { message: String },

    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Permission denied: {action}")]
    PermissionDenied { action: String },
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Config(_) => 2,
            CliError::Command(CommandError::NotFound { .. }) => 3,
            CliError::Command(CommandError::PermissionDenied { .. }) => 4,
            CliError::Auth(_) => 5,
            CliError::Validation(_) => 6,
            _ => 1,
        }
    }
}
```

## 🧪 CLI TESTING

```rust
// tests/cli_tests.rs
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_help_command() {
    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("A CLI tool with multiple commands"));
}

#[test]
fn test_version_command() {
    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_database_status_command() {
    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.args(["db", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Checking database status"));
}

#[test]
fn test_database_status_json_output() {
    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.args(["--format", "json", "db", "status"])
        .assert()
        .success()
        .stdout(predicate::str::is_json());
}

#[test]
fn test_server_start_with_custom_address() {
    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.args(["server", "start", "--address", "0.0.0.0:3000"])
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .success();
}

#[test]
fn test_config_validation() {
    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.path().join("invalid.json");
    std::fs::write(&config_file, "{ invalid json }").unwrap();

    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.args(["--config", config_file.to_str().unwrap(), "db", "status"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to parse JSON config"));
}

#[test]
fn test_interactive_commands() {
    // Test with simulated user input
    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.args(["db", "restore", "--input", "backup.sql"])
        .write_stdin("n\n") // Simulate "no" answer
        .assert()
        .success()
        .stdout(predicate::str::contains("Aborted by user"));
}

#[test]
fn test_force_commands() {
    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.args(["db", "init", "--force"])
        .write_stdin("y\n") // Simulate "yes" answer
        .assert()
        .success()
        .stdout(predicate::str::contains("Database initialized successfully"));
}

#[test]
fn test_verbose_output() {
    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.args(["-vv", "db", "status"])
        .assert()
        .success();
}

#[test]
fn test_invalid_subcommand() {
    let mut cmd = Command::cargo_bin("mycli").unwrap();
    cmd.arg("invalid")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}
```

## 📝 CLI BEST PRACTICES CHECKLIST

```markdown
## CLI Implementation Verification

### Command Structure
- [ ] Uses clap 4.0+ with derive features
- [ ] Implements subcommand architecture for complex CLIs
- [ ] CommandExecutor trait with async support
- [ ] enum_dispatch for efficient command routing
- [ ] Clear command hierarchy and organization

### Argument Handling
- [ ] Global arguments (config, verbose, format, etc.)
- [ ] Subcommand-specific arguments with validation
- [ ] Environment variable integration
- [ ] Help text and descriptions for all commands
- [ ] Value enums for restricted choices

### Error Handling
- [ ] Structured error types with thiserror
- [ ] User-friendly error messages
- [ ] Appropriate exit codes for different error types
- [ ] Proper error context and chaining
- [ ] Graceful handling of interrupted operations

### User Experience
- [ ] Colored output with terminal detection
- [ ] Progress bars for long-running operations
- [ ] Interactive prompts for destructive actions
- [ ] Multiple output formats (text, JSON, YAML)
- [ ] Confirmation dialogs for dangerous operations

### Configuration
- [ ] File-based configuration support (JSON/YAML)
- [ ] Environment variable overrides
- [ ] Sensible defaults for all options
- [ ] Configuration validation and error reporting
- [ ] Multiple configuration sources

### Testing
- [ ] Integration tests with assert_cmd
- [ ] Command output validation
- [ ] Error condition testing
- [ ] Interactive command testing
- [ ] Configuration file testing

### Documentation
- [ ] Comprehensive help text
- [ ] Examples in command descriptions
- [ ] Shell completion support
- [ ] Manual page generation
- [ ] Usage examples in README

### Performance
- [ ] Async operations for I/O bound tasks
- [ ] Progress indicators for slow operations
- [ ] Efficient argument parsing
- [ ] Minimal startup time
- [ ] Appropriate timeout handling

### Security
- [ ] Input validation for all arguments
- [ ] Safe file operations with proper permissions
- [ ] Secure handling of sensitive data
- [ ] Protection against path traversal
- [ ] Proper cleanup of temporary resources
```

This comprehensive CLI standard ensures robust, user-friendly, and maintainable command-line applications following modern Rust patterns and clap best practices.

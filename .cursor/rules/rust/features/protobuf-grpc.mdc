---
description:
globs:
alwaysApply: false
---
# 🛜 RUST PROTOBUF & GRPC STANDARDS

> **TL;DR:** Modern protobuf and gRPC patterns using prost/tonic 0.13+ with clean code generation, Inner data structures, MessageSanitizer trait, gRPC reflection, and simplified service implementations.

## 🔍 PROTOBUF & GRPC DESIGN STRATEGY

```mermaid
graph TD
    Start["gRPC Service Design"] --> ProtoDesign["Protocol Buffer Design"]

    ProtoDesign --> CodeGen["Code Generation"]
    CodeGen --> DataStructures["Data Structure Design"]

    DataStructures --> InnerTypes["Inner Types Pattern"]
    DataStructures --> Sanitization["Message Sanitization"]

    InnerTypes --> BusinessLogic["Business Logic Separation"]
    Sanitization --> BusinessLogic

    BusinessLogic --> ServiceImpl["Service Implementation"]
    ServiceImpl --> ErrorHandling["Error Handling"]

    ErrorHandling --> Testing["Service Testing"]
    Testing --> Reflection["gRPC Reflection"]
    Reflection --> Deployment["Service Deployment"]

    Deployment --> Monitoring["Monitoring & Observability"]
    Monitoring --> Production["Production gRPC Service"]

    style Start fill:#4da6ff,stroke:#0066cc,color:white
    style InnerTypes fill:#4dbb5f,stroke:#36873f,color:white
    style Sanitization fill:#ffa64d,stroke:#cc7a30,color:white
    style ServiceImpl fill:#d94dbb,stroke:#a3378a,color:white
```

## 🎯 PROTOBUF & GRPC FRAMEWORK REQUIREMENTS

### Prost/Tonic Configuration
- **Use prost/tonic latest versions** - Modern protobuf and gRPC implementation
- **Clean code generation** - Organized pb module structure with proper imports
- **Inner data structures** - Simplified, optional-free data structures for business logic
- **MessageSanitizer trait** - Consistent data transformation patterns
- **Simplified service methods** - Clean separation between gRPC and business logic

## 📦 PROTOBUF & GRPC DEPENDENCIES

```toml
# Cargo.toml - Protobuf & gRPC dependencies
[dependencies]
# Core protobuf and gRPC
prost = "0.13"
prost-types = "0.13"
tonic = { version = "0.13", features = ["gzip", "tls", "tls-roots", "compression"] }

# Build-time dependencies
[build-dependencies]
prost-build = "0.13"
tonic-build = { version = "0.13", features = ["prost"] }

# Data structures and serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
typed_builder = "0.18"

# Error handling
anyhow = "1.0"
thiserror = "2.0"

# Async runtime
tokio = { version = "1.45", features = ["macros", "rt-multi-thread", "signal"] }
tokio-stream = { version = "0.1", features = ["net"] }

# Logging and tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# Optional: Additional features
tower = "0.4"                    # Middleware
tower-http = { version = "0.5", features = ["trace", "cors"] }
uuid = { version = "1.0", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }

[dev-dependencies]
tonic-health = "0.13"           # Health check service
tonic-reflection = "0.13"       # gRPC reflection service
```

## 🏗️ PROTOBUF & GRPC ARCHITECTURE

```mermaid
graph TD
    Proto["Proto Files"] --> Build["build.rs"]
    Build --> Generate["Code Generation"]
    Generate --> PbModule["src/pb/ Module"]

    PbModule --> Generated["Generated Structs<br>(Foo, Bar, etc.)"]
    PbModule --> Services["Generated Services<br>(GreeterService, etc.)"]

    Generated --> Inner["Inner Structs<br>(FooInner, BarInner)"]
    Generated --> Sanitizer["MessageSanitizer<br>Implementation"]

    Inner --> Business["Business Logic<br>Methods"]
    Services --> Trait["Service Trait<br>Implementation"]

    Business --> Trait
    Sanitizer --> Trait

    Trait --> Server["gRPC Server"]

    style Proto fill:#4da6ff,stroke:#0066cc,color:white
    style Build fill:#4dbb5f,stroke:#36873f,color:white
    style Inner fill:#ffa64d,stroke:#cc7a30,color:white
    style Sanitizer fill:#d94dbb,stroke:#a3378a,color:white
```

## 🚀 BUILD CONFIGURATION

### build.rs Setup

```rust
// build.rs
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pb_dir = PathBuf::from("src/pb");

    // Ensure pb directory exists
    if !pb_dir.exists() {
        std::fs::create_dir_all(&pb_dir)?;
    }

    // Configure tonic-build with prost_types
    let mut tonic_build = tonic_build::configure()
        .out_dir(&pb_dir)
        .format(true)  // Enable code formatting with prettyplease
        .build_server(true)
        .build_client(true)
        .build_transport(true)  // Include transport utilities
        .emit_rerun_if_changed(false)  // We handle this manually
        // Use prost_types instead of compile_well_known_types
        .extern_path(".google.protobuf.Timestamp", "::prost_types::Timestamp")
        .extern_path(".google.protobuf.Duration", "::prost_types::Duration")
        .extern_path(".google.protobuf.Empty", "::prost_types::Empty")
        .extern_path(".google.protobuf.Any", "::prost_types::Any")
        .extern_path(".google.protobuf.Struct", "::prost_types::Struct")
        .extern_path(".google.protobuf.Value", "::prost_types::Value");

    // Compile proto files
    let proto_files = [
        "proto/greeting.proto",
        "proto/user.proto",
        "proto/common.proto",
    ];

    // Generate file descriptor set for reflection
    tonic_build
        .file_descriptor_set_path(&pb_dir.join("greeter_descriptor.bin"))
        .compile(&proto_files, &["proto"])?;

    // Generate mod.rs file
    generate_mod_file(&pb_dir)?;

    // Rename generated files for better organization
    rename_generated_files(&pb_dir)?;

    // Emit rerun-if-changed directives
    println!("cargo:rerun-if-changed=proto/");
    println!("cargo:rerun-if-changed=build.rs");

    // Emit rerun-if-env-changed for protoc
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");

    Ok(())
}

fn generate_mod_file(pb_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut mod_content = String::new();
    mod_content.push_str("// Auto-generated module file\n");
    mod_content.push_str("// DO NOT EDIT MANUALLY\n\n");

    // Add file descriptor set for reflection
    mod_content.push_str("/// File descriptor set for gRPC reflection\n");
    mod_content.push_str("pub const GREETER_FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(\"greeter_descriptor.bin\");\n\n");

    // Scan for generated .rs files
    for entry in std::fs::read_dir(pb_dir)? {
        let entry = entry?;
        let path = entry.path();

        if let Some(extension) = path.extension() {
            if extension == "rs" {
                if let Some(file_stem) = path.file_stem() {
                    let module_name = file_stem.to_string_lossy();
                    if module_name != "mod" {
                        mod_content.push_str(&format!("pub mod {};\n", module_name));
                    }
                }
            }
        }
    }

    // Write mod.rs file
    let mod_file_path = pb_dir.join("mod.rs");
    std::fs::write(mod_file_path, mod_content)?;

    Ok(())
}

fn rename_generated_files(pb_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Rename files like "a.b.rs" to "b.rs" or "a/b.rs" based on naming conflicts
    for entry in std::fs::read_dir(pb_dir)? {
        let entry = entry?;
        let path = entry.path();

        if let Some(file_name) = path.file_name() {
            let file_name_str = file_name.to_string_lossy();

            // Check if file has package prefix (contains dots)
            if file_name_str.contains('.') && file_name_str.ends_with(".rs") {
                let parts: Vec<&str> = file_name_str
                    .strip_suffix(".rs")
                    .unwrap()
                    .split('.')
                    .collect();

                if parts.len() > 1 {
                    // Use the last part as the new file name
                    let new_name = format!("{}.rs", parts.last().unwrap());
                    let new_path = pb_dir.join(&new_name);

                    // Check for conflicts
                    if !new_path.exists() {
                        std::fs::rename(&path, &new_path)?;
                        println!("Renamed {} to {}", file_name_str, new_name);
                    } else {
                        // Create subdirectory structure
                        let package_name = parts[0];
                        let package_dir = pb_dir.join(package_name);
                        std::fs::create_dir_all(&package_dir)?;

                        let new_path = package_dir.join(&new_name);
                        std::fs::rename(&path, &new_path)?;
                        println!("Moved {} to {}/{}", file_name_str, package_name, new_name);
                    }
                }
            }
        }
    }

    Ok(())
}
```

### Project Structure

```
my-grpc-service/
├── proto/                       # Protocol buffer definitions
│   ├── common.proto            # Common types and enums
│   ├── greeting.proto          # Greeting service definition
│   └── user.proto              # User service definition
├── src/
│   ├── pb/                     # Generated protobuf code
│   │   ├── mod.rs              # Auto-generated module file
│   │   ├── common.rs           # Generated from common.proto
│   │   ├── greeting.rs         # Generated from greeting.proto
│   │   └── user.rs             # Generated from user.proto
│   ├── inner/                  # Inner data structures
│   │   ├── mod.rs
│   │   ├── common.rs           # CommonInner types
│   │   ├── greeting.rs         # GreetingInner types
│   │   └── user.rs             # UserInner types
│   ├── services/               # Service implementations
│   │   ├── mod.rs
│   │   ├── greeting.rs         # Greeting service impl
│   │   └── user.rs             # User service impl
│   ├── sanitizers/             # MessageSanitizer implementations
│   │   ├── mod.rs
│   │   └── mod_common.rs
│   ├── lib.rs                  # Library root
│   └── main.rs                 # Server binary
├── build.rs                    # Build script
└── Cargo.toml
```

## 🏛️ CORE TRAITS AND PATTERNS

### MessageSanitizer Trait

```rust
// src/sanitizers/mod.rs
use crate::inner;

/// Trait for sanitizing protobuf messages into clean Inner types
pub trait MessageSanitizer {
    type Output;

    /// Convert protobuf message to clean Inner type with proper defaults
    fn sanitize(self) -> Self::Output;
}

// Use standard From trait instead of custom ToProtobuf trait

// Common sanitization utilities for complex types only

pub fn sanitize_timestamp(opt: Option<prost_types::Timestamp>) -> chrono::DateTime<chrono::Utc> {
    opt.map(|ts| {
        chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
            .unwrap_or_default()
    })
    .unwrap_or_else(chrono::Utc::now)
}
```

### Example Proto Definition

```protobuf
// proto/greeting.proto
syntax = "proto3";

package greeting.v1;

import "google/protobuf/timestamp.proto";
import "common.proto";

// Greeting service definition
service GreeterService {
  rpc SayHello(HelloRequest) returns (HelloReply);
  rpc SayHelloStream(HelloRequest) returns (stream HelloReply);
  rpc GetUserGreeting(UserGreetingRequest) returns (UserGreetingReply);
}

// Request message for saying hello
message HelloRequest {
  string name = 1;
  optional string language = 2;
  optional common.v1.UserContext user_context = 3;
  optional google.protobuf.Timestamp request_time = 4;
}

// Reply message for hello
message HelloReply {
  string message = 1;
  string language = 2;
  optional google.protobuf.Timestamp reply_time = 3;
  optional common.v1.ServerInfo server_info = 4;
}

message UserGreetingRequest {
  string user_id = 1;
  optional string custom_message = 2;
}

message UserGreetingReply {
  string greeting = 1;
  optional common.v1.UserProfile user_profile = 2;
}
```

```protobuf
// proto/common.proto
syntax = "proto3";

package common.v1;

message UserContext {
  string user_id = 1;
  string session_id = 2;
  repeated string roles = 3;
}

message ServerInfo {
  string version = 1;
  string environment = 2;
  string instance_id = 3;
}

message UserProfile {
  string id = 1;
  string name = 2;
  string email = 3;
  bool is_active = 4;
}
```

## 📊 INNER DATA STRUCTURES

### Inner Types Implementation

```rust
// src/inner/common.rs
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypedBuilder)]
pub struct UserContextInner {
    #[builder(default, setter(into))]
    pub user_id: String,
    #[builder(default, setter(into))]
    pub session_id: String,
    #[builder(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypedBuilder)]
pub struct ServerInfoInner {
    #[builder(default = "1.0.0".to_string(), setter(into))]
    pub version: String,
    #[builder(default = "development".to_string(), setter(into))]
    pub environment: String,
    #[builder(default_code = "Uuid::new_v4().to_string()", setter(into))]
    pub instance_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypedBuilder)]
pub struct UserProfileInner {
    #[builder(default, setter(into))]
    pub id: String,
    #[builder(default, setter(into))]
    pub name: String,
    #[builder(default, setter(into))]
    pub email: String,
    #[builder(default = true)]
    pub is_active: bool,
}
```

```rust
// src/inner/greeting.rs
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;
use chrono::{DateTime, Utc};
use super::common::{UserContextInner, ServerInfoInner, UserProfileInner};

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypedBuilder)]
pub struct HelloRequestInner {
    #[builder(setter(into))]
    pub name: String,
    #[builder(default = "en".to_string(), setter(into))]
    pub language: String,
    #[builder(default, setter(strip_option))]
    pub user_context: Option<UserContextInner>,
    #[builder(default_code = "Utc::now()")]
    pub request_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypedBuilder)]
pub struct HelloReplyInner {
    #[builder(default, setter(into))]
    pub message: String,
    #[builder(default = "en".to_string(), setter(into))]
    pub language: String,
    #[builder(default_code = "Utc::now()")]
    pub reply_time: DateTime<Utc>,
    #[builder(default, setter(strip_option))]
    pub server_info: Option<ServerInfoInner>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypedBuilder)]
pub struct UserGreetingRequestInner {
    #[builder(default, setter(into))]
    pub user_id: String,
    #[builder(default, setter(into))]
    pub custom_message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypedBuilder)]
pub struct UserGreetingReplyInner {
    #[builder(default, setter(into))]
    pub greeting: String,
    #[builder(default)]
    pub user_profile: UserProfileInner,
}
```

## 🔄 MESSAGE SANITIZER IMPLEMENTATIONS

```rust
// src/sanitizers/greeting.rs
use crate::{
    pb::greeting::*,
    inner::{greeting::*, common::*},
    sanitizers::{MessageSanitizer, sanitize_timestamp}
};
use chrono::{DateTime, Utc};

impl MessageSanitizer for HelloRequest {
    type Output = HelloRequestInner;

    fn sanitize(self) -> Self::Output {
        HelloRequestInner::builder()
            .name(self.name)
            .language(self.language.unwrap_or_default())
            .user_context(self.user_context.map(|ctx| ctx.sanitize()))
            .request_time(
                self.request_time
                    .map(|ts| {
                        DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
                            .unwrap_or_else(Utc::now)
                    })
                    .unwrap_or_else(Utc::now)
            )
            .build()
    }
}

impl From<HelloRequestInner> for HelloRequest {
    fn from(inner: HelloRequestInner) -> Self {
        Self {
            name: inner.name,
            language: if inner.language.is_empty() { None } else { Some(inner.language) },
            user_context: inner.user_context.map(|ctx| ctx.into()),
            request_time: Some(prost_types::Timestamp {
                seconds: inner.request_time.timestamp(),
                nanos: inner.request_time.timestamp_subsec_nanos() as i32,
            }),
        }
    }
}

impl MessageSanitizer for HelloReply {
    type Output = HelloReplyInner;

    fn sanitize(self) -> Self::Output {
        HelloReplyInner::builder()
            .message(self.message)
            .language(self.language)
            .reply_time(
                self.reply_time
                    .map(|ts| {
                        DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
                            .unwrap_or_else(Utc::now)
                    })
                    .unwrap_or_else(Utc::now)
            )
            .server_info(self.server_info.map(|info| info.sanitize()))
            .build()
    }
}

impl From<HelloReplyInner> for HelloReply {
    fn from(inner: HelloReplyInner) -> Self {
        Self {
            message: inner.message,
            language: inner.language,
            reply_time: Some(prost_types::Timestamp {
                seconds: inner.reply_time.timestamp(),
                nanos: inner.reply_time.timestamp_subsec_nanos() as i32,
            }),
            server_info: inner.server_info.map(|info| info.into()),
        }
    }
}

impl MessageSanitizer for UserGreetingRequest {
    type Output = UserGreetingRequestInner;

    fn sanitize(self) -> Self::Output {
        UserGreetingRequestInner::builder()
            .user_id(self.user_id)
            .custom_message(self.custom_message.unwrap_or_default())
            .build()
    }
}

impl From<UserGreetingRequestInner> for UserGreetingRequest {
    fn from(inner: UserGreetingRequestInner) -> Self {
        Self {
            user_id: inner.user_id,
            custom_message: if inner.custom_message.is_empty() {
                None
            } else {
                Some(inner.custom_message)
            },
        }
    }
}

impl MessageSanitizer for UserGreetingReply {
    type Output = UserGreetingReplyInner;

    fn sanitize(self) -> Self::Output {
        UserGreetingReplyInner::builder()
            .greeting(self.greeting)
            .user_profile(
                self.user_profile
                    .map(|profile| profile.sanitize())
                    .unwrap_or_default()
            )
            .build()
    }
}

impl From<UserGreetingReplyInner> for UserGreetingReply {
    fn from(inner: UserGreetingReplyInner) -> Self {
        Self {
            greeting: inner.greeting,
            user_profile: Some(inner.user_profile.into()),
        }
    }
}
```

```rust
// src/sanitizers/common.rs
use crate::{
    pb::common::*,
    inner::common::*,
    sanitizers::MessageSanitizer
};

impl MessageSanitizer for UserContext {
    type Output = UserContextInner;

    fn sanitize(self) -> Self::Output {
        UserContextInner::builder()
            .user_id(self.user_id)
            .session_id(self.session_id)
            .roles(self.roles)
            .build()
    }
}

impl From<UserContextInner> for UserContext {
    fn from(inner: UserContextInner) -> Self {
        Self {
            user_id: inner.user_id,
            session_id: inner.session_id,
            roles: inner.roles,
        }
    }
}

impl MessageSanitizer for ServerInfo {
    type Output = ServerInfoInner;

    fn sanitize(self) -> Self::Output {
        ServerInfoInner::builder()
            .version(self.version)
            .environment(self.environment)
            .instance_id(self.instance_id)
            .build()
    }
}

impl From<ServerInfoInner> for ServerInfo {
    fn from(inner: ServerInfoInner) -> Self {
        Self {
            version: inner.version,
            environment: inner.environment,
            instance_id: inner.instance_id,
        }
    }
}

impl MessageSanitizer for UserProfile {
    type Output = UserProfileInner;

    fn sanitize(self) -> Self::Output {
        UserProfileInner::builder()
            .id(self.id)
            .name(self.name)
            .email(self.email)
            .is_active(self.is_active)
            .build()
    }
}

impl From<UserProfileInner> for UserProfile {
    fn from(inner: UserProfileInner) -> Self {
        Self {
            id: inner.id,
            name: inner.name,
            email: inner.email,
            is_active: inner.is_active,
        }
    }
}
```

## 🛠️ SERVICE IMPLEMENTATION PATTERN

### Business Logic Implementation

```rust
// src/services/greeting.rs
use anyhow::Result;
use tracing::{info, instrument};
use crate::inner::{greeting::*, common::*};

pub struct GreeterService {
    server_info: ServerInfoInner,
}

impl GreeterService {
    pub fn new() -> Self {
        Self {
            server_info: ServerInfoInner::builder()
                .version(env!("CARGO_PKG_VERSION").to_string())
                .environment(std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()))
                .build(),
        }
    }

    /// Business logic for saying hello - clean and testable
    #[instrument(skip(self))]
    pub async fn say_hello_inner(
        &self,
        request: HelloRequestInner,
    ) -> Result<HelloReplyInner> {
        info!("Processing hello request for user: {}", request.name);

        let greeting = match request.language.as_str() {
            "es" => format!("¡Hola, {}!", request.name),
            "fr" => format!("Bonjour, {}!", request.name),
            "de" => format!("Hallo, {}!", request.name),
            "ja" => format!("こんにちは、{}さん!", request.name),
            _ => format!("Hello, {}!", request.name),
        };

        let reply = HelloReplyInner::builder()
            .message(greeting)
            .language(request.language.clone())
            .server_info(Some(self.server_info.clone()))
            .build();

        Ok(reply)
    }

    /// Business logic for user-specific greeting
    #[instrument(skip(self))]
    pub async fn get_user_greeting_inner(
        &self,
        request: UserGreetingRequestInner,
    ) -> Result<UserGreetingReplyInner> {
        info!("Processing user greeting request for user: {}", request.user_id);

        // Simulate user lookup (in real app, this would be a database call)
        let user_profile = UserProfileInner::builder()
            .id(request.user_id.clone())
            .name(format!("User_{}", request.user_id))
            .email(format!("user_{}@example.com", request.user_id))
            .is_active(true)
            .build();

        let greeting = if !request.custom_message.is_empty() {
            format!("{}, {}!", request.custom_message, user_profile.name)
        } else {
            format!("Welcome back, {}!", user_profile.name)
        };

        let reply = UserGreetingReplyInner::builder()
            .greeting(greeting)
            .user_profile(user_profile)
            .build();

        Ok(reply)
    }
}

impl Default for GreeterService {
    fn default() -> Self {
        Self::new()
    }
}
```

### gRPC Service Trait Implementation

```rust
// src/services/greeting.rs (continued)
use tonic::{Request, Response, Status, Code};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use crate::{
    pb::greeting::{
        greeter_service_server::GreeterService as GreeterServiceTrait,
        HelloRequest, HelloReply, UserGreetingRequest, UserGreetingReply
    },
    sanitizers::{MessageSanitizer, ToProtobuf}
};

#[tonic::async_trait]
impl GreeterServiceTrait for GreeterService {
    /// gRPC trait implementation - thin wrapper around business logic
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let remote_addr = request.remote_addr();
        let request_inner = request.into_inner().sanitize();

        match self.say_hello_inner(request_inner).await {
            Ok(reply_inner) => {
                info!("Successful hello response to {:?}", remote_addr);
                let reply = reply_inner.into();
                Ok(Response::new(reply))
            }
            Err(e) => {
                tracing::error!("Error processing hello request: {}", e);
                Err(Status::new(Code::Internal, "Internal server error"))
            }
        }
    }

    /// Streaming response example
    type SayHelloStreamStream = ReceiverStream<Result<HelloReply, Status>>;

    async fn say_hello_stream(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<Self::SayHelloStreamStream>, Status> {
        let request_inner = request.into_inner().sanitize();
        let (tx, rx) = tokio::sync::mpsc::channel(128);

        // Clone necessary data for the async task
        let service = self.clone();

        tokio::spawn(async move {
            for i in 0..5 {
                let mut req = request_inner.clone();
                req.name = format!("{} ({})", req.name, i + 1);

                match service.say_hello_inner(req).await {
                    Ok(reply_inner) => {
                        let reply = reply_inner.into();
                        if tx.send(Ok(reply)).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(format!("Error: {}", e)))).await;
                        break;
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_user_greeting(
        &self,
        request: Request<UserGreetingRequest>,
    ) -> Result<Response<UserGreetingReply>, Status> {
        let request_inner = request.into_inner().sanitize();

        match self.get_user_greeting_inner(request_inner).await {
            Ok(reply_inner) => {
                let reply = reply_inner.into();
                Ok(Response::new(reply))
            }
            Err(e) => {
                tracing::error!("Error processing user greeting request: {}", e);
                Err(Status::new(Code::Internal, "Internal server error"))
            }
        }
    }
}

// Make service cloneable for streaming
impl Clone for GreeterService {
    fn clone(&self) -> Self {
        Self {
            server_info: self.server_info.clone(),
        }
    }
}
```

## 🏁 SERVER SETUP

### Main Server Implementation

```rust
// src/main.rs
use anyhow::Result;
use tonic::transport::Server;
use tonic_health::server::health_reporter;
use tonic_reflection::server::ServerReflectionServer;
use tower_http::trace::TraceLayer;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod pb;
mod inner;
mod sanitizers;
mod services;

use pb::greeting::greeter_service_server::GreeterServiceServer;
use services::greeting::GreeterService;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with structured logging
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
        )
        .init();

    let addr = "127.0.0.1:50051".parse()?;
    info!("Starting gRPC server on {}", addr);

        // Create health reporter
    let (mut health_reporter, health_service) = health_reporter();

    // Create reflection service for service discovery
    let reflection_service = ServerReflectionServer::configure()
        .register_encoded_file_descriptor_set(pb::GREETER_FILE_DESCRIPTOR_SET)
        .build()
        .unwrap();

    // Set service as serving
    health_reporter
        .set_serving::<GreeterServiceServer<GreeterService>>()
        .await;

    // Create services
    let greeter_service = GreeterService::new();

    // Start server with enhanced configuration
    Server::builder()
        .layer(TraceLayer::new_for_grpc())
        .timeout(std::time::Duration::from_secs(30))
        .concurrency_limit_per_connection(256)
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
        .add_service(health_service)
        .add_service(reflection_service)
        .add_service(GreeterServiceServer::new(greeter_service))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Signal received, starting graceful shutdown");
}
```

### Library Root

```rust
// src/lib.rs
pub mod pb;
pub mod inner;
pub mod sanitizers;
pub mod services;

// Re-export commonly used types
pub use inner::*;
pub use sanitizers::MessageSanitizer;
pub use services::*;

// Health check endpoint for service discovery
pub async fn health_check() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Basic health check logic
    Ok(())
}
```

## 🧪 TESTING PATTERNS

### Unit Tests for Business Logic

```rust
// src/services/greeting.rs (test module)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::inner::{greeting::*, common::*};

    #[tokio::test]
    async fn test_say_hello_english() {
        let service = GreeterService::new();
        let request = HelloRequestInner::builder()
            .name("World".to_string())
            .language("en".to_string())
            .build();

        let result = service.say_hello_inner(request).await.unwrap();

        assert_eq!(result.message, "Hello, World!");
        assert_eq!(result.language, "en");
        assert!(result.server_info.is_some());
    }

    #[tokio::test]
    async fn test_say_hello_spanish() {
        let service = GreeterService::new();
        let request = HelloRequestInner::builder()
            .name("Mundo".to_string())
            .language("es".to_string())
            .build();

        let result = service.say_hello_inner(request).await.unwrap();

        assert_eq!(result.message, "¡Hola, Mundo!");
        assert_eq!(result.language, "es");
    }

    #[tokio::test]
    async fn test_get_user_greeting_default() {
        let service = GreeterService::new();
        let request = UserGreetingRequestInner::builder()
            .user_id("123".to_string())
            .build();

        let result = service.get_user_greeting_inner(request).await.unwrap();

        assert_eq!(result.greeting, "Welcome back, User_123!");
        assert_eq!(result.user_profile.id, "123");
        assert_eq!(result.user_profile.email, "user_123@example.com");
        assert!(result.user_profile.is_active);
    }

    #[tokio::test]
    async fn test_get_user_greeting_custom() {
        let service = GreeterService::new();
        let request = UserGreetingRequestInner::builder()
            .user_id("456".to_string())
            .custom_message("Good morning".to_string())
            .build();

        let result = service.get_user_greeting_inner(request).await.unwrap();

        assert_eq!(result.greeting, "Good morning, User_456!");
    }
}
```

### Integration Tests for gRPC Service

```rust
// tests/integration_test.rs
use anyhow::Result;
use tonic::Request;
use my_grpc_service::{
    pb::greeting::{
        greeter_service_server::GreeterServiceServer,
        greeter_service_client::GreeterServiceClient,
        HelloRequest
    },
    services::greeting::GreeterService
};

#[tokio::test]
async fn test_grpc_say_hello() -> Result<()> {
    // Start test server
    let (client, _server) = setup_test_server().await?;

    // Make request
    let request = Request::new(HelloRequest {
        name: "Integration Test".to_string(),
        language: Some("en".to_string()),
        user_context: None,
        request_time: Some(prost_types::Timestamp {
            seconds: chrono::Utc::now().timestamp(),
            nanos: 0,
        }),
    });

    let response = client.say_hello(request).await?;
    let reply = response.into_inner();

    assert_eq!(reply.message, "Hello, Integration Test!");
    assert_eq!(reply.language, "en");

    Ok(())
}

async fn setup_test_server() -> Result<(GreeterServiceClient<tonic::transport::Channel>, tokio::task::JoinHandle<()>)> {
    use tonic::transport::{Server, Channel, Endpoint};
    use std::net::SocketAddr;

    let addr: SocketAddr = "127.0.0.1:0".parse()?;
    let greeter_service = GreeterService::new();

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;

    let server_handle = tokio::spawn(async move {
        Server::builder()
            .timeout(std::time::Duration::from_secs(10))
            .add_service(GreeterServiceServer::new(greeter_service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create channel with connection configuration
    let channel = Endpoint::from_shared(format!("http://{}", addr))?
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(5))
        .connect()
        .await?;
    let client = GreeterServiceClient::new(channel);

    Ok((client, server_handle))
}
```

## 📝 PROTOBUF & GRPC BEST PRACTICES CHECKLIST

```markdown
## Protobuf & gRPC Implementation Verification

### Code Generation
- [ ] Uses prost/tonic 0.13+ versions
- [ ] Generated code placed in src/pb/ directory
- [ ] build.rs includes format(true) with prettyplease
- [ ] File descriptor set generated for reflection
- [ ] Auto-generated mod.rs file references all modules
- [ ] Files renamed from package.name.rs to name.rs format
- [ ] No naming conflicts in generated files
- [ ] Proto3 optional fields properly configured

### Inner Data Structures
- [ ] Inner structs created for all protobuf messages
- [ ] Inner structs use TypedBuilder for construction
- [ ] Inner structs include proper derives (Debug, Clone, Default, Serialize, Deserialize)
- [ ] Inner structs remove unnecessary Option wrappers
- [ ] Inner structs use appropriate default values

### MessageSanitizer Implementation
- [ ] All protobuf messages implement MessageSanitizer trait
- [ ] Sanitization handles Option fields properly
- [ ] Default values provided for missing fields
- [ ] Timestamp conversion handled correctly
- [ ] ToProtobuf trait implemented for reverse conversion

### Service Implementation
- [ ] Business logic methods use Inner types only
- [ ] Business logic methods are easily testable
- [ ] gRPC trait implementation is thin wrapper
- [ ] Error handling converts business errors to gRPC Status
- [ ] Streaming responses handled properly
- [ ] Request/response logging implemented

### Project Structure
- [ ] Clear separation: pb/, inner/, sanitizers/, services/
- [ ] Module organization follows domain boundaries
- [ ] build.rs handles code generation properly
- [ ] Proto files organized by service/domain
- [ ] Common types extracted to shared proto files

### Testing
- [ ] Unit tests for business logic methods
- [ ] Integration tests for gRPC endpoints
- [ ] Tests use Inner types for simple construction
- [ ] Test server setup for integration testing
- [ ] Error cases covered in tests

### Performance & Reliability
- [ ] Connection pooling for clients (if needed)
- [ ] Proper timeout and keepalive configuration
- [ ] Health check service implemented
- [ ] gRPC reflection service enabled
- [ ] Concurrency limits configured
- [ ] Graceful shutdown handling
- [ ] Structured tracing and logging configured
- [ ] Compression enabled (gzip/deflate/zstd)

### Security
- [ ] Input validation in business logic
- [ ] Authentication/authorization patterns
- [ ] TLS configuration for production
- [ ] Rate limiting considerations
- [ ] Error messages don't leak sensitive data
```

This comprehensive protobuf and gRPC standard ensures clean, testable, and maintainable code following modern Rust patterns with prost/tonic.

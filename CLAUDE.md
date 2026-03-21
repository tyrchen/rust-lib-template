# {{ project-name }}

IMPORTANT: Never enter plan mode automatically!!! Never enter plan mode automatically!!!

## Core Principles

### Code Quality

- **SOLID and DRY Principles**: Maintain clean, maintainable code following SOLID and DRY principles
- **No Incomplete Code**: Never write TODO comments or temporary solutions. If you encounter such a situation:
  1. Stop the current task
  2. Review the problem globally
  3. Rethink the design and identify the best alternative solutions
  4. Proceed with the complete solution
- **Thorough Analysis**: Always perform a comprehensive review and analysis of the problem before starting work
- Do not suppress dead code, remove them; Unless explicitly requested, do not go through deprecation process, just remove the code that is no longer needed.

### Development Workflow

- **Latest Dependencies**: Always search the web for the latest dependencies or helm charts or resources and their current usage patterns. If doing a deep research, put the research doc under ./docs/research. You shall look into that directory before doing researches.
- **Automation via Makefile**:
  - Explore existing Makefile targets and use them accordingly
  - For new automation tasks, always add a Makefile target instead of creating shell scripts
  - Keep automation consistent and discoverable

## Documentation

For specs, explore ./specs directory and put it to the right place, name the spec file as {feature-name}-{type}.md and update index.md accordingly. type can be prd, design, impl-plan, verification-plan, review, etc.

For docs, explore ./docs directory and put it to the right place, and update index.md accordingly. If you generate documentation that wasn't explicitly requested, make sure to place it under `./docs` and follow the same rule.

## Toolchain & Build

- Always use Rust 2024 edition with latest stable version. Pin version in `rust-toolchain.toml`.
- Always run `cargo build`, `cargo test`, `cargo +nightly fmt`, and `cargo clippy -- -D warnings` before finishing the task.
- Use `cargo clippy -- -D warnings -W clippy::pedantic` for stricter linting. Allow specific lints with justification.
- Run `cargo audit` regularly to check for security vulnerabilities in dependencies.
- Use `cargo-deny` to enforce license policies and ban specific crates.
- Enable all rustc lints in Cargo.toml: `#![warn(rust_2024_compatibility, missing_docs, missing_debug_implementations)]`.
- DO NOT use `cargo clean` at any time. If you indeed need it, ask user for permission

## Error Handling

- Never use `unwrap()` or `expect()` in production code. Always handle errors properly with `?` operator or explicit match.
- Use `thiserror` for library error types (with custom error enums). Use `anyhow` for application error handling.
- Implement proper error context with `.context()` or `.with_context()` when propagating errors.
- Use `Result<T>` as return type for fallible functions. Never use `Option` to represent errors.
- For unrecoverable errors in applications, use `panic!`. For libraries, always return `Result`.
- Define domain-specific error types using enums with `thiserror`. Include source errors with `#[source]`.

## Async & Concurrency

- Use Tokio as async runtime. Always specify features explicitly (e.g., `tokio = { version = "1", features = ["rt-multi-thread", "macros"] }`).
- Prefer message passing (channels) over shared state. Use `tokio::sync::mpsc` for MPSC, `flume` for faster channels.
- Organize system into subsystems using Actor model. Each actor owns its state and communicates via channels. For non-Send/Sync types (e.g., Tantivy Index), isolate in dedicated thread and use channels for communication. Never wrap in Mutex/RwLock. For Actors, it shall have proper start/stop/restart logic. Consider using AtomicBool for shutdown signal.
- Use `DashMap` for concurrent HashMap instead of `Mutex<HashMap>` or `RwLock<HashMap>`. Provides better performance.
- Use `ArcSwap` for infrequently updated shared data (e.g., configuration). Allows lock-free reads.
- Always consider using config crate for configuration management. Always use yaml format for configuration. For data that shall be tuned at runtime, put in configuration file. For data that shall be tuned at compile time, use compile time constants.
- For async traits, use native `async fn` in traits (stable since Rust 1.75). **Exception**: When traits require object safety (used with `dyn Trait` for dynamic dispatch like `Arc<dyn TaskStorage>`), use `async-trait` crate and document the reason in module-level docs.
- Always handle task panics. Use `tokio::spawn` with proper error handling. Consider `tokio::task::JoinSet` for managing multiple tasks.
- Avoid blocking operations in async contexts. Use `tokio::task::spawn_blocking` for CPU-intensive or blocking operations.
- Use structured concurrency patterns. Ensure spawned tasks are awaited or explicitly detached with justification.

## Type Design & API

- Use `typed-builder` crate for builder pattern on structs with more than 5 fields. Provides compile-time guarantees. Use plain `new()` for simple constructors with few arguments.
- Make types as specific as possible. Prefer `NonZeroU32` over `u32` when zero is invalid.
- Implement `Debug` for all types. Use `#[derive(Debug)]` or implement manually with sensitive data redaction.
- Make structs non-exhaustive with `#[non_exhaustive]` for library types to allow future field additions.
- Use enums for state machines. Prefer type-state pattern for compile-time state enforcement when applicable.
- Use Rust's type system to make illegal states unrepresentable. Encode invariants in types, not runtime checks.
- Do not use `Option<T>` when `T` has a default value (e.g. Vec/HashMap/HashSet). Use `Option<T>` only when `T` is truly optional.
- always prefer to use From / TryFrom / FromStr traits for type conversion. For parsing a string with certain grammar, prefer to use latest version of winnow.

## Safety & Security

- Never use `unsafe` blocks, even in test code. If absolutely necessary, document safety invariants thoroughly.
- Always validate and sanitize external input (user input, network data, file content), use `validator` crate for validation when necessary.
- Use `rustls` with `aws-lc-rs` crypto backend for TLS. Never use `native-tls` or OpenSSL bindings.
- Use constant-time comparison for cryptographic values. Use `subtle` crate's `ConstantTimeEq`.
- Never log, print, or expose sensitive data (passwords, tokens, keys). Implement `Debug` carefully for sensitive types.
- Use `secrecy` crate for handling secrets in memory (prevents accidental logging/exposure).
- For test environment variables, use `dotenvy` crate. Never hard-code credentials.

## Serialization & Data

- Use `serde` for serialization. Always use `#[serde(rename_all = "camelCase")]` for JSON compatibility.
- Use `#[serde(rename = "...")]` for individual field mapping. Use `#[serde(alias = "...")]` for backward compatibility.
- Use `#[serde(default)]` for optional fields with default values. Define custom defaults with `#[serde(default = "path::to::fn")]`.
- Use `#[serde(skip_serializing_if = "Option::is_none")]` to omit null fields in JSON output.
- Validate deserialized data immediately. Use custom deserialize functions with validation logic when needed.
- Use `serde_json::Value` only when schema is truly dynamic. Prefer strongly-typed structs.

## Testing

- Write unit tests in the same file using `#[cfg(test)] mod tests`. Write integration tests in `tests/` directory.
- Use descriptive test names with `test_should_` prefix describing behavior (e.g., `test_should_return_error_on_invalid_input`).
- Use `rstest` for parameterized tests. Use `proptest` for property-based testing of invariants.
- Test error cases explicitly. Ensure error types and messages are correct with `assert!(matches!(...))`.
- Use `mockall` or `wiremock` for mocking external dependencies. Avoid over-mocking; prefer real implementations when fast.
- Aim for high test coverage but focus on critical paths and edge cases over raw coverage percentage.
- Use `#[ignore]` for slow tests. Run with `cargo test -- --ignored` in CI.
- Write documentation tests in doc comments. These serve as examples and are automatically tested.

## Logging & Observability

- Use `tracing` for structured logging and diagnostics. Never use `println!` or `dbg!` in production code.
- Use appropriate log levels: `error!` for errors, `warn!` for warnings, `info!` for important events, `debug!` and `trace!` for diagnostics.
- Add context with `tracing::instrument` on async functions. Include relevant fields: `#[instrument(skip(large_param))]`.
- Use `tracing-subscriber` for configuring output. Use JSON format for production, human-readable for development.
- Implement spans for tracking request/operation lifecycle. Use `span.in_scope()` or `instrument` macro.

## Performance

- Profile before optimizing. Use `cargo flamegraph`, `perf`, or `samply` for profiling.
- Avoid unnecessary allocations. Use `&str` instead of `String`, prefer borrowing over cloning.
- Bring in bytes when necessary and prefer Bytes related data structure over Vec on handling payload.
- Avoid unnecessary cloning, use Arc or related data structure when necessary.
- Use `Vec::with_capacity()` when final size is known. Pre-allocate collections to avoid reallocation.
- Use iterators instead of explicit loops. Iterators are often optimized better and compose well.
- Use `SmallVec` for small vectors that usually fit on stack. Use `smallbox` for small heap allocations.
- Use `Cow<str>` when data might be borrowed or owned. Avoids clones when borrowing is possible.
- For hot paths, consider using `#[inline]` or `#[inline(always)]` with justification.
- Use latest `criterion` crate for performance benchmarking. Do not do benchmark test in early development stage.

## Dependencies

- Minimize dependencies. Each dependency increases compile time, binary size, and attack surface.
- Pin versions carefully. Use `~` for patch updates (`tokio = "~1.40"`), `^` for minor updates (default).
- Prefer pure Rust crates over FFI bindings. They're safer, more portable, and easier to audit.
- Audit new dependencies before adding. Check maintenance status, security history, and code quality.
- Use workspace dependencies for shared dependencies across crates: `[workspace.dependencies]`.

## Documentation

- Write doc comments (`///`) for all public items. Include examples in doc comments.
- Use `//!` for module-level documentation. Explain module purpose and usage patterns.
- Write at least one example in doc comments for public functions. Examples are tested automatically.
- Use `# Errors`, `# Panics`, `# Safety` sections in doc comments to document failure modes.
- Generate docs with `cargo doc --open`. Ensure docs render correctly with proper formatting.

## Code Style

- always import `use` dependencies in the top of the file in the following order: std, deps, local modules.
- Use specific imports (`use xxx::yyy::ZZZ`) and reference types/functions directly by name (`ZZZ`) in code. Never use fully qualified paths in function/structure/trait implementations. Exception: macros may use fully qualified paths when necessary.
- Follow Rust naming conventions: `snake_case` for functions/variables, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Keep functions small and focused. Embrace KISS principle. Extract complex logic into well-named functions. Unless absolutely necessary, function should not be more than 150 lines of code.
- Prefer explicit types over `impl Trait` in public APIs for clarity. Use `impl Trait` for internal functions.
- Never use `todo!()` during development. Always have a plan and a clear path to complete the task.
- Order items consistently: imports, constants, types, functions, tests. Use `rustfmt` for automatic formatting.
- Use trailing commas in multi-line function calls and struct literals for cleaner diffs.

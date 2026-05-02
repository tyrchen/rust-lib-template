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

Two complementary disciplines. **Safety** is about Rust's memory and concurrency guarantees — keep the soundness contract intact so the compiler can prove correctness. **Security** is about hostile input from the outside world — validate at the boundary, defense in depth, assume any single layer will fail. Treat every value crossing a trust boundary (HTTP, IPC, files, env vars, CLI args, deserialization, message queues) as hostile until proven otherwise.

### Rust Safety

- **No `unsafe`**: `#![forbid(unsafe_code)]` at the crate root. Never use `unsafe` blocks, including in tests. If a dependency genuinely requires it, isolate behind a thin safe wrapper, document every safety invariant, and add a fuzz harness — `unsafe` is a contract you sign with the compiler, and breaking it is undefined behavior.
- **No panics on external input**: `unwrap()`, `expect()`, `[]` indexing, `unreachable!()`, `todo!()`, `panic!()` reachable from user data is a DoS vector and a soundness liability. Use `?`, `.get()`, `try_into()`, explicit `match`. Lint boundary modules with `cargo clippy -W clippy::unwrap_used -W clippy::indexing_slicing -W clippy::panic -W clippy::expect_used`.
- **No undefined behavior**: No transmute between unrelated types, no aliasing `&mut`, no uninitialized reads, no out-of-bounds. If `cargo +nightly miri test` would flag it, fix it.
- **Checked arithmetic on external values**: Use `checked_*`/`saturating_*`/`wrapping_*` explicitly when arithmetic touches user input. Default `+` panics in debug and silently wraps in release — both are wrong for security-sensitive code.
- **No data races**: Rust's `Send`/`Sync` rule out data races at compile time — don't fight the type system with `Mutex<RefCell<_>>` or interior mutability tricks. Prefer message passing (channels) over shared state, as `Async & Concurrency` covers.
- **FFI boundaries**: When calling C, the FFI surface is `unsafe` by definition — wrap it in a safe Rust API that upholds invariants (null-check pointers, validate lengths, take ownership clearly). Never expose raw `*mut T` to safe callers.
- **Soundness > convenience**: A safe API that's slightly awkward beats an `unsafe` shortcut. If you find yourself reaching for `unsafe` for performance, profile first — `unsafe` is rarely the bottleneck.

### Input Validation

- **Validate at the boundary**: Run validation immediately at deserialization/parse time, before any business logic touches the value. Once a value enters the domain, it must already be valid — no "we'll check this later".
- **Reject, don't sanitize**: Prefer rejecting invalid input over cleaning it. Sanitization has bypasses (encoding tricks, double-encoding, Unicode normalization, homoglyphs); rejection has none. Strip-and-continue is a code smell.
- **Length limits on every string**: Every `String`/`&str` derived from external input must have an explicit maximum length, enforced in **bytes** (not chars) to defeat multi-byte exhaustion. Real attack seen in the wild: `User-Agent` headers containing entire `<html>` documents to balloon logs, DB rows, and downstream parsers — even fields you "don't care about" need caps. Default cap unknown fields to something small (e.g. 256 bytes) and raise deliberately.
- **Charset allowlists, never blocklists**: Define what's permitted, never what's forbidden. Blocklists are always incomplete (Unicode confusables, control chars, RTL overrides, zero-width spaces, NUL bytes). Use regex allowlists like `^[a-zA-Z0-9_-]{1,64}$` for identifiers, slugs, and free-form short fields.
- **Bound every collection**: `Vec<T>`, `HashMap<K, V>`, `HashSet<T>` from external input must have explicit element-count caps in addition to per-element validation. An unbounded `Vec<u8>` of length-bounded strings is still a memory exhaustion vector.
- **Numeric ranges**: Bound every integer from external input. `u32` is not a range; an explicit `1..=1000` is. Use `validator`'s `range` or a newtype with a fallible constructor.
- **Newtype every domain primitive**: Wrap validated values in newtypes with private fields and a fallible constructor (`UserId(u64)`, `Email(String)`, `Slug(String)`, `UserAgent(String)`). Validation runs once in `new`/`try_from`; every downstream use is provably safe by construction. This is the type system enforcing security invariants.
- **Use the `validator` crate**: For struct-level validation, derive `Validate` and annotate fields with `#[validate(length(max = 256), regex = "...", email, url, range(min = 1, max = 1000))]`. Call `.validate()` immediately after deserialization — `serde` checks shape, not semantics.
- **Make illegal states unrepresentable**: `NonZeroU32`, `NonEmpty<T>`, state-machine enums, `#[serde(deny_unknown_fields)]`. Don't runtime-check what the type system can prove at compile time.

### Injection Prevention

- **SQL**: Always parameterize. `sqlx::query!`, `diesel`, `sea-orm` bound parameters. `format!("... WHERE id = {}", id)` is a CVE waiting for a PR.
- **Shell**: Use `Command::new("foo").arg(user_input)` (argv form). Never `sh -c` with concatenated user input. Prefer a Rust crate over shelling out at all.
- **Path traversal**: For user-supplied filenames, reject `..`, absolute paths, NUL bytes, and OS-specific separators up front. Then canonicalize and verify `canonical.starts_with(allowed_root)`. Symlinks defeat naïve checks — re-canonicalize after open when possible.
- **URL / SSRF**: Parse with `url::Url`, allowlist schemes (`https` only for outbound), resolve the hostname yourself and reject private/loopback/link-local ranges (`10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`). Pin the resolved IP for the connection — don't re-resolve, or DNS rebinding wins.
- **HTML / templating**: Render user content through auto-escaping templates (`askama`, `maud`, `tera` with autoescape on). Never `format!` user data into HTML.
- **Regex (ReDoS)**: Use the `regex` crate (linear-time guarantee). Never `fancy-regex`/`pcre`/`onig` on untrusted input. If accepting untrusted regex *patterns*, set `RegexBuilder::size_limit` and `dfa_size_limit`, and reject patterns over a length cap before compile.
- **Log injection**: Use `tracing` structured fields, never string-concatenate user input into log lines. Strip/escape newlines and control chars in any user value that does land in a message.

### Resource Limits & DoS

- **Body size**: HTTP servers cap request body at the framework layer (`axum::extract::DefaultBodyLimit`, `tower_http::limit::RequestBodyLimitLayer`). Set to the smallest size that supports legitimate traffic, not "comfortably large".
- **Timeouts**: Every network and disk IO operation needs a timeout (`tokio::time::timeout`). Per-request, per-connection, per-upstream-call. No exceptions.
- **Concurrency caps**: Bound concurrent in-flight work with `tokio::sync::Semaphore` or `tower::limit`. An unbounded `tokio::spawn` per request is a fork bomb.
- **Recursion limits**: Set explicit depth limits for nested parsing (JSON, XML, protobuf). Review `serde_json`'s default recursion limit and lower it for untrusted input.
- **Decompression bombs**: For gzip/zstd/brotli input, use streaming decoders wrapped with a byte-counting `Read` that errors past a hard limit. Never `read_to_end` on a decompressor fed from the network.
- **Integer overflow**: Use `checked_*`/`saturating_*` explicitly when arithmetic touches external values. Debug-panic + release-wrap is the worst combination for security-sensitive code.
- **Rate limiting**: Per-IP and per-account limits on auth, signup, password reset, search, and any unauthenticated endpoint (`tower_governor`, `governor`).

### Cryptography & Secrets

- **TLS**: `rustls` with the `aws-lc-rs` crypto backend. Never `native-tls`, OpenSSL bindings, or `rustls` + `ring` for new code.
- **Constant-time comparison**: `subtle::ConstantTimeEq` for tokens, MACs, signatures, password hashes — anything where timing leaks information.
- **Password hashing**: `argon2` (id variant) with parameters tuned for ≥250ms on target hardware. Never MD5/SHA-1/SHA-256/bcrypt for new code.
- **Randomness**: `rand::rngs::OsRng` or `getrandom` for tokens/keys/nonces/IDs. Never `thread_rng()` for security-sensitive randomness — it is not contractually CSPRNG-strength across versions.
- **Secret types**: Wrap in `secrecy::SecretString`/`SecretBox`. `Debug` redacts; access requires explicit `expose_secret()`. For custom types containing credentials, implement `Debug` manually and add a unit test asserting redacted output.
- **No secrets in logs/errors/panics**: `error!("failed: {req:?}")` will happily leak the `Authorization` header. Build a redacting `Debug` for request types, or `#[serde(skip)]`/skip the field in tracing.
- **Secret loading**: From env (`dotenvy` for tests only) or a secret manager. Never hard-code, never commit `.env*`, never bake into binaries. Run a secret scanner in pre-commit / CI.
- **Key rotation**: Design APIs to support multiple active keys simultaneously so rotation does not require a redeploy.

### AuthN / AuthZ

- **AuthN every request**: No endpoints trusting network position. Zero trust at the application layer.
- **AuthZ every action**: Permission check at the operation level, not at the route. IDOR is the #1 web-app CVE class — `GET /docs/{id}` must verify *this caller can read doc id*.
- **Session tokens**: ≥256 bits of CSPRNG entropy, stored hashed server-side, transmitted as `HttpOnly; Secure; SameSite=Lax` cookies for browser flows.
- **Don't roll your own auth**: Use `axum-login`, `oauth2`, `openidconnect`. Custom auth is where CVEs live.

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

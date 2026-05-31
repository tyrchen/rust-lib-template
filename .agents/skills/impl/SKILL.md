---
name: impl
description: Implement one phase of ./specs/91-impl-plan.md end-to-end with high quality bars (correctness, elegance, performance), then run an independent code review against the relevant specs and fix every valid finding before declaring done. Use whenever the user says "build phase N", "implement the next phase", "land M0/M1/M2/M3", "follow the impl plan", "ship phase X entirely", "based on @specs/91-impl-plan.md think ultra hard and build phase X", or asks for a phase-shaped slice of the spec set. Trigger even when the user does not say "impl" if they reference an impl plan / roadmap milestone and ask Codex to build it.
---

# Impl

Land one phase from `./specs/91-impl-plan.md` to a publishable bar — no TODOs, no half-finished modules, no quality-gate bypasses — then run a thorough independent review against the spec and fix every valid finding before claiming done. The phase is the unit of completion; partial phases create drift the spec set is meant to prevent.

## When this fires

- "build phase N entirely" / "implement phase N" / "land M<n>"
- "based on `@specs/91-impl-plan.md` and other specs in `./specs`, follow `@AGENTS.md`, think ultra hard, build phase X"
- "previous phases are done — continue with the next one"
- "ship the spec; one phase at a time"
- The user names a milestone (M0/M1/M2/M3) or a Phase-N task and asks Codex to write the code

## What this skill is *not*

- Not for one-off bug fixes or feature requests outside a planned phase. Use direct edits.
- Not for greenfield design work. If `./specs/` is empty or the relevant phase is not specified, hand off to the **spec** skill first.
- Not for prototyping. The quality bar here is "publishable"; throwaway code lives somewhere else.

## Diagram expectation

When an implementation phase changes architecture, data flow, processing flow, lifecycle/state transitions, or build/dependency order, update the corresponding spec or research diagrams in the same phase. Use fenced ASCII-style diagrams (` ```text `) with nested boxes or grouped lanes for non-trivial systems, matching the spec/research skill standard. Prefer terminal-safe box-drawing characters (`┌─┐│└┘`, `▼`, `▲`) when they make ownership and runtime boundaries clearer. For request/protocol flows, use vertical lifelines with numbered steps so the ordering is reviewable. Do not leave diagrams as stale prose-adjacent decorations; they must show the real components, channels, storage, external systems, state transitions, and failure/shutdown paths that changed.

## Workflow

### 1. Bind the scope

Resolve which phase to build, exactly:

- Read `./specs/91-impl-plan.md` and find the requested phase. If the user named a milestone (M0/M1), translate it via the roadmap (`90-roadmap.md`) — milestones and phases pair 1:1 but are numbered differently.
- Read every spec section the phase tasks cite. The impl plan's task table has a "Spec" column for a reason.
- Read `./docs/research/` memos referenced by those specs. Their decisions bind the implementation.
- Read project `AGENTS.md` (and global `~/.codex/AGENTS.md`). Engineering norms (error handling, async, type design, security, logging) apply unconditionally.
- Read `./vendors/` references the spec or research cites — for prior art and exact API shapes.

If a previous phase is *not* fully landed (per its exit criteria), say so and offer to land it first. Do not paper over a gap by starting later.

### 2. Plan the phase

Before code:

- Write a TaskCreate entry per row in the phase's task table. Status starts pending; mark in_progress one at a time.
- Identify any task that has unresolved dependencies on specs or research. If anything is unclear, ask the user **before writing code**, not after.
- Check the phase's exit criteria. Those are the conditions for "done"; if you cannot articulate them now, you cannot meet them later.

### 3. Implement, task by task

- Work through tasks in the order the impl plan lists them. The order is dependency-correct; deviating without reason invites retrofits.
- For each task: smallest reasonable PR-shaped commit; passing tests local to that change; no `TODO` / `unimplemented!()` / `todo!()` / dead-code suppressions.
- **Match the spec exactly.** If you find yourself diverging — wrong API name, different invariant, different envelope shape — stop. Either the spec is wrong (record it in the project's deferred-findings spec — see § "Deferred-findings backlog" below — and get the user's call), or your reading is. Drift kills spec sets.
- Make illegal states unrepresentable. If the spec lists invariants, encode them in types — newtypes, sealed traits, type-state, `NonZero*`, `NonEmpty<T>`.
- Performance budgets in the spec are not aspirational. If the phase task table cites a budget, write the bench (`criterion`) and run it before claiming the task complete.

### 3a. Rust engineering norms (binding — anchor: AGENTS.md)

Project `AGENTS.md` and `~/.codex/AGENTS.md` define the binding Rust norms for this codebase — error model, async/concurrency patterns, type design, safety/security rules, serde shapes, testing conventions, observability, performance, dependencies, code style. **Read both before writing code in this phase** and apply every applicable section unconditionally; they are not aspirational.

Do not paraphrase AGENTS.md here — it is already loaded into your context. Open it, follow it. The recurring high-leverage sections in order: *Error Handling*, *Async & Concurrency*, *Type Design & API*, *Safety & Security*, *Serialization*, *Testing*, *Logging & Observability*, *Performance*, *Dependencies*, *Code Style*.

If a spec for this phase silently relaxes a AGENTS.md rule, the spec is wrong: record it in the deferred-findings backlog and raise it before writing code. If you genuinely need to deviate at a specific call site (e.g. a single `#[allow(...)]`), the commit message must name the `file:line` and the reason — reviewers will check.

### 4. Select and run relevant quality gates

After each meaningful task and again before claiming the phase complete, inspect `git diff --name-only` and the phase exit criteria. Run the checks that exercise the changed surface; do not run Rust build/test/clippy for docs-only, spec-only, or skill-only changes that cannot affect Rust behaviour.

Use this matrix:

- Rust source, tests, examples, `build.rs`, feature flags, `Cargo.toml`, `Cargo.lock`, or generated Rust artifacts changed:

  ```bash
  cargo build --workspace --all-targets
  cargo test  --workspace --all-targets
  cargo +nightly fmt -- --check
  cargo clippy --workspace --all-targets -- -D warnings
  ```

- Public Rust API docs, doctests, or intra-doc links changed:

  ```bash
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
  ```

- Boundary modules or code touching external input changed:

  ```bash
  cargo clippy --workspace --all-targets -- \
    -D warnings -W clippy::pedantic \
    -W clippy::unwrap_used -W clippy::expect_used \
    -W clippy::indexing_slicing -W clippy::panic
  ```

- Dependencies, lockfiles, license policy, supply-chain config, or release packaging changed:

  ```bash
  cargo deny check
  cargo audit
  ```

- Documentation, specs, research memos, AGENTS/CLAUDE instructions, or skills changed without touching Rust-affecting inputs: proofread/render the changed Markdown where useful, verify touched links and indexes, run `make check-agent-sync` for AGENTS/CLAUDE/skill edits, and run skill frontmatter validation for changed skill folders.

If the project has a `Makefile` with relevant gates wired (`make check` / `make ci` / narrower targets), prefer that — keeps the gates discoverable.

**Never** bypass a relevant gate (`--no-verify`, allow-by-default lints introduced for one site, ignored tests). If a gate fails, fix the underlying cause. If a heavyweight gate is not relevant to the diff, say why instead of running it mechanically.

### 5. Verify exit criteria

The phase has explicit exit criteria in the impl plan. Each one is observable: a test passes, a bench fits a budget, a behaviour can be demonstrated. Show evidence for each — paste the green output, the bench number, or a one-line repro. "Looks done" is not done.

If a phase exit criterion is *blocked* by something the user must decide (a credential, a third-party endpoint), say so explicitly and stop. Do not claim done.

### 6. Commit

Stage with named paths (never `git add -A`). One commit, or a small ordered series; either way the message names the phase and the milestone:

```
phase <N>: <one-line summary>

<paragraph: what landed; which spec sections; which exit criteria are met>

<paragraph: known follow-ups, deferred items, links to research memos>
```

### 7. Independent code review

This is the load-bearing step. The phase is **not done** until reviewed against the spec and the valid findings fixed.

- Spawn a code-review subagent (`Agent` tool) with `subagent_type: "general-purpose"` (or a project-specific reviewer if one is configured). Brief the agent like a colleague who hasn't seen this conversation:

  > Review the diff for phase `<N>` against `./specs/<the relevant specs by number>` and `./docs/research/<relevant memos>`. The phase is supposed to deliver `<exit criteria>`. The senior architect persona expects: spec adherence (concrete, correct, elegant, performant); AGENTS.md compliance (error handling, async, type design, safety/security); no TODOs / dead code / silent fallbacks; matching invariants between spec and code; tests covering the phase's exit criteria. Cite findings as `path:LINE` with severity P0/P1/P2/P3 and a recommended fix shape. Do not propose redesigns; defer those to the project's deferred-findings backlog spec.

- The agent runs read-only and produces a finding list. Read it carefully.

- Categorise findings:
  - **Valid + in-phase** — fix in this phase before claiming done.
  - **Valid + out-of-phase** — append to the deferred-findings backlog spec (see below) with severity, file:line, and fix shape. Do not silently inflate scope.
  - **Invalid** — note why in the response so the user can sanity-check the call.

- Fix the in-phase findings. Re-run the relevant quality gates for the changed surface. If a fix is non-trivial, commit separately ("phase N review: fix <P-id>") so history shows the review pass.

- If a finding reveals a **spec defect** (the spec is wrong, not the code), record it in the deferred-findings backlog and surface it to the user before patching either side. Spec drift here is exactly what the spec set exists to prevent.

#### Deferred-findings backlog

Out-of-phase findings, deferred items, and surfaced spec defects need a single home so they don't get lost. Where this lives is a project choice — the obs project uses `./specs/93-improvements-review.md`, but any single Markdown file under `./specs/` (or wherever the project's `AGENTS.md` directs) works as long as it is the *one* canonical location for the team. If the project does not yet have one, create it and note in the commit message; if it does, append. Each entry should include severity (P0/P1/P2/P3), `file:line` citation, and a one-line fix shape so the next phase can pick it up without re-deriving the context.

### 8. Hand off

Final report to the user, in this shape:

- **Phase**: N — `<one-line description>`.
- **Specs covered**: `<list of NN-…md sections>`.
- **Exit criteria**: each criterion with `✅` + evidence (test name, bench number, command output).
- **Files changed**: high-level summary, not a file list.
- **Review**: number of findings, P0/P1 fixed in this phase, P2/P3 deferred to `93` with citations.
- **Next phase**: which phase is unlocked, what its first task is.

## Quality bar

- Spec adherence is binary, not "mostly". Either the API matches and the invariants hold, or you stop and reconcile spec ↔ code in writing.
- No `TODO`, `unimplemented!`, `todo!`, `panic!("not yet")`. If a piece of work cannot be completed in this phase, it does not belong in this phase — defer via a deferred-findings entry.
- No dead code suppressions. If something is unused, remove it.
- Tests are part of the deliverable, not an afterthought. Each public surface introduced has at least one happy-path test and one error-path test; load-bearing invariants get property tests where the shape allows.
- Bench harnesses ship alongside any task with a perf budget; CI gates the regression.
- Every public item has `///` docs; every crate has `//!` module docs; doc tests compile.

## Common failure modes (avoid)

- **"Phase done" with the review skipped.** The review is the load-bearing checkpoint. Always run it.
- **Refactor smear.** Touching files outside the phase's scope. Resist; defer to `93` and keep the diff focused.
- **`unwrap` in a "non-critical" path.** All paths reachable from external input are critical. Use `?`, `match`, `try_into`.
- **Implicit `clone()` everywhere.** Borrow first; `Cow` where ambiguous; `Arc` for shared ownership; clone last.
- **`Mutex<HashMap>` instead of `DashMap`** (the project's AGENTS.md is explicit on this — follow it).
- **Adding features the spec did not request.** If it's not in the spec for this phase, it is out of scope. Either update the spec first or land later.
- **Skipping scoped verification.** Rust code changes need Rust gates such as `cargo +nightly fmt` and `cargo clippy -D warnings`; docs-only changes need docs/sync validation instead. Do not substitute one for the other.
- **`git reset --hard` to recover from confusion.** Never. Investigate; ask the user; preserve work. The git reflog is your friend.

## Cross-references

- The **spec** skill produces `./specs/91-impl-plan.md`; this skill consumes it.
- The **research** skill produces `./docs/research/<spike|study>-*.md`; this skill respects their decisions.
- The project's deferred-findings backlog spec under `./specs/` (whatever the project names it; obs uses `93-improvements-review.md`) is the single home for findings deferred out of the current phase.
- `./specs/99-key-decisions.md` is the canonical record of *why*; if your code conflicts with a decision there, escalate to the user before writing.

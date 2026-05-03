---
name: research
description: Vendor reference repos as git submodules under ./vendors and produce deep research memos under ./docs/research covering architecture, design, key data structures, and load-bearing algorithms. Use whenever the user says "do research on X", "study how Y works", "submodule this repo and look into it", "understand the design of Z before we start", "spike on …", references prior-art crates / repos that should be evaluated, or asks to refer to ./vendors before designing or implementing. Trigger even when the user does not say the word "research" if they paste GitHub URLs and ask Claude to learn from them, compare alternatives, or extract patterns.
---

# Research

Capture prior art with rigour: vendor the upstream code, read it deeply, write a memo that future you (and the spec / impl skills) can rely on. Memos are load-bearing; they pin assumptions before code is written so spec drift and rework do not happen later.

## When this fires

- "do deep research on `<repo>`" / "study how `<repo>` works"
- "submodule `<urls>` to `./vendors`" / "vendor `<repo>` for reference"
- "before we design X, look into how `<crate>` does it"
- "spike on `<assumption>`" — a single-question, time-boxed memo
- The user pastes GitHub URLs and asks Claude to learn from them
- The spec or impl skill needs prior-art before proceeding and there is no memo yet

If `./docs/research/` already contains a relevant memo, **read it first** and decide whether to update it instead of writing a new one. Do not duplicate.

## What to produce

For each topic, exactly one memo at `./docs/research/<kind>-<slug>.md` plus an updated `./docs/index.md` (or wherever the project's `CLAUDE.md` says research lives). Three memo kinds, picked by intent:

- **`spike-<slug>.md`** — a single, sharp, time-boxed question ("does `ArcSwap<Arc<dyn T>>` compose?", "is `linkme` reliable on macOS arm64 release+LTO?"). Validates one assumption with a runnable artefact. ≤ 2 pages.
- **`study-<slug>.md`** — a deep-dive into one or more vendored repos ("how `tokio-rs/tracing` resolves dispatcher per call site", "how `defmt` interns log strings", "comparing how `prost` / `quick-protobuf` / `buffa` handle unknown fields"). 3–10 pages, cites file paths and line numbers.
- **`survey-<slug>.md`** — pure web / docs research where vendoring is not warranted ("latest `axum` middleware patterns", "current state of Rust async cancellation"). Cite the latest stable version of each source, link to upstream docs / blog posts / RFCs, and note the date — surveys go stale faster than spikes or studies.

Always pick the narrowest kind that fits; specificity beats breadth.

## Workflow

1. **Confirm scope** — Restate in one sentence what question the memo will answer. If it is broad ("how does tracing work"), force it narrower until it names a specific subsystem, decision, or invariant. A memo with no question becomes a wiki page nobody reads.

2. **Vendor the repo** — for any upstream code that will be cited:

   ```bash
   git submodule add <url> vendors/<name>
   git submodule update --init --recursive
   ```

   Pin to a specific commit (`git -C vendors/<name> rev-parse HEAD`) and record it in the memo. If the user names a tag/branch, check it out before pinning. Vendor whenever you need grep / Read / git-blame access to upstream source; being on crates.io is not a reason to skip vendoring (the obs project vendored `tracing`, `defmt`, and others precisely to read their internals). For pure API browsing without reading internals, `cargo doc --open` is enough.

   For broad studies that compare alternatives, multiple vendored repos in one memo is fine — name each one's pin in the header.

3. **Read with intent** — open the vendored tree with `Read` / `Grep` / `Explore` agent. Three passes:

   - **Map**: `Cargo.toml`, top-level `lib.rs` / `mod.rs`, README, `ARCHITECTURE.md` if any. Sketch the module graph.
   - **Hot path**: trace the most-trafficked code path end-to-end (emit, dispatch, encode, flush…). Note every allocation, lock, and atomic.
   - **Edge cases**: panic paths, drop order, async cancellation, FFI boundaries, `unsafe` blocks. These are where the design's assumptions live.

   Rust-specific reading aids when the structure is non-obvious: `cargo doc --document-private-items --no-deps` to see private surfaces, `cargo expand` (in a tiny driver crate) to see what macros generate, `cargo asm` / `cargo-show-asm` for hot-path codegen questions. Use them sparingly — they are tools, not deliverables.

   Quote real `vendors/<name>/path/to/file.rs:LINE` citations in the memo so a reader can verify without re-finding the code.

4. **Validate spikes with running code** — for `spike-*.md`, write a tiny standalone crate under `/tmp/<repo>-spikes/<slug>/`, run it, paste the output. A spike without a runnable artefact is a guess. Bench with `criterion --quick` when latency claims are made.

5. **Write the memo** using the template below. Keep it terse: a future reader (often the spec skill) wants the **decision** and the **why**, not a tour.

6. **Wire it in** — append the memo to `./docs/index.md` under a "Research" section (create the file if missing). If the project's CLAUDE.md says research goes elsewhere, follow CLAUDE.md.

## Memo template

Spikes (single-question, time-boxed):

```markdown
# Spike: <question, one line>

Status: <Done|In progress> · Owner: <team> · Date: <YYYY-MM-DD> · Outcome: **<PASS|FAIL|PASS-with-caveat>**

## Question

The spec / design assumption being tested, copied verbatim or with a precise reference. State what fails if this assumption is wrong.

## Method

The runnable artefact: crate path, deps + versions resolved, hardware, the exact thing measured. Reproducible in one paragraph.

## Findings

Numbered, terse, evidence-backed. Each finding cites `vendors/<repo>/path:LINE` or pasted output. Use ✅ / ⚠ / ❌ markers for at-a-glance scanning.

## Decision

**GO / NO-GO / GO-with-amendments**, plus the *implementation rules* the spec must adopt as a result. This is the load-bearing section.

## Risks identified

What could still bite us, with a follow-up plan or a CI gate that pins the assumption regression-tested.
```

Studies (broad architectural deep-dive):

```markdown
# Study: <subsystem in <repo>>

Status: <Done|In progress> · Owner: <team> · Date: <YYYY-MM-DD> · Vendor pin: `vendors/<repo>` @ `<sha>`

## Why this study

What downstream design / spec / code needs this knowledge. If nothing needs it, do not write it.

## Architecture map

Module graph (text or mermaid). Name the load-bearing types and the trait boundaries.

## Hot path walkthrough

Trace the dominant code path step by step with `vendors/<repo>/path:LINE` citations. Call out each allocation, lock, atomic, and async boundary.

## Key data structures

For each: shape, invariants, who mutates, who reads, why it was chosen over alternatives. One paragraph each.

## Key algorithms

For each: input/output, complexity, correctness argument. Include a small trace example if non-obvious.

## What we will adopt

Concrete patterns, types, trait shapes we will copy or adapt. Cite the exact upstream lines.

## What we will avoid

Patterns that look attractive but do not fit our constraints, and *why*. Future reviewers will ask; answer once here.

## Open questions

Anything that needs a follow-up spike. Each item gets a `spike-<slug>.md` filename so it can be picked up later.
```

## Quality bar

- A memo is **done** when a teammate who has not opened the vendored repo can answer the memo's question and cite the upstream lines that justify the answer.
- Every claim about behaviour cites a file path + line number, not a vague reference.
- Every claim about performance has a number with units and the bench harness used.
- **No vendored copy of code in the memo body** — link to `vendors/<repo>/...:LINE` instead. Quoting is fine for ≤ 5 lines when the structure is the point.
- Do not write TODOs in the memo. If something is unknown, write "open question" + a spike filename so it is tracked, not buried.

## Anti-patterns

- A "research doc" that is really a redesign — if you find yourself proposing your own architecture, stop; that belongs in `./specs/`, not `./docs/research/`.
- Vendoring 10 repos and skimming all of them. Pick one, read it deeply, write the memo, then move on.
- Memos that conclude "more investigation needed" without naming what specifically. Always name the next concrete artefact.

## Hand-off

When the memo is committed, point the user (and the next skill) to:

- the memo path,
- the upstream commit pin (for spikes/studies) or sources + date (for surveys),
- the headline takeaway in one sentence — for a spike, the GO/NO-GO decision; for a study, the patterns adopted/avoided; for a survey, the recommended approach.

The spec skill will cite this memo by path; the impl skill will rely on the decision / patterns.

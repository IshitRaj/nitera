<p align="center">
  <img src="assets/nitera-logo.png" width="120" alt="Nitera logo" />
</p>

<h1 align="center">
  Nitera
  <br/>
  <a href="https://crates.io/crates/nitera">
    <img src="https://img.shields.io/crates/v/nitera.svg" alt="Crates.io version" />
  </a>
  <br/>
</h1>

<p align="center">
  A zero-dependency policy engine for filesystem, process, and network access in Rust.
</p>

#

## Documentation

This README covers the core API, policy format, and current behavior. For a more detailed reference covering the public API, crate structure, parser, policy evaluation, path handling, and testing, see [`DOCUMENTATION.md`](DOCUMENTATION.md).

## What Nitera does

Nitera sits between your application code and `std::fs`, `std::process`, and `std::net`. Every filesystem read, write, delete, or create, every spawned command, and every outbound connection you route through the `Nitera` API is checked against a policy file before it runs. The policy decides whether the operation is allowed outright, denied outright, or requires an explicit approval at runtime.

Nitera has no external dependencies. The `.nitera` file parser and everything else is built on the Rust standard library alone.

## Installation

Nitera is published on [crates.io](https://crates.io/crates/nitera). Add it with:

```bash
cargo add nitera
```

or add it directly to `Cargo.toml`:

```toml
[dependencies]
nitera = "1.0.0"
```

## Quick start

```rust
use nitera::Nitera;

fn main() {
    let nitera = Nitera::load(".nitera").expect("failed to load policy");

    nitera.write("output/report.txt", b"hello").expect("write failed");
    let content = nitera.read("output/report.txt").expect("read failed");

    println!("{}", String::from_utf8_lossy(&content));
}
```

## Policy files (`.nitera`)

```text
[filesystem]
allow read ./projects/**
allow write ./playground/**
allow create ./playground/**
ask delete ./playground/**

[process]
allow command cargo, rustc
ask command rm
allow scope ./playground/**

[network]
allow host api.github.com
ask host *.internal.example.com
```

Every rule falls into `allow`, `ask`, or `deny`. If a request doesn't match any rule at all, it's denied by default, nothing is implicitly allowed. If more than one rule could match, Nitera checks in this order: `deny` first, then `ask`, then `allow`. The most restrictive match always wins.

**Filesystem** rules are split into `read`, `write`, `delete`, and `create`, each with its own independent list. A `create` rule covers both files and folders: `Nitera::create(path, "text")` creates a new file containing the supplied bytes, while `Nitera::create_dir(path)` creates one new directory level.

```rust
nitera.create("playground/notes.txt", "some text")?;
nitera.create_dir("playground/logs")?;
```

**Process** rules gate on the command name (`allow command cargo, rustc`) and separately require a `scope`, a path glob the working directory must fall inside. Scope is checked first: a command run outside every listed scope is denied even if that exact command is on the allow list.

**Network** rules match on host.

Note there is no `deny host *` catch-all above, and none is needed: unmatched hosts are already denied. If you do add one, it overrides every other host rule, because `deny` is checked first, so `allow host api.github.com` next to `deny host *` would leave `api.github.com` denied.

Paths can be relative, absolute, or `~`-prefixed, and support `*` (single segment) and `**` (any depth) globs.

## How checks work

`Nitera::load()` prepares path patterns once. Checks use a scan for small or broad rule sets and a sorted prefix index for larger, selective sets. The index only selects candidates; the matcher still checks each candidate, with `deny` taking priority over `ask`, then `allow`.

Guarded operations (`read`, `write`, `delete`, `create`, `create_dir`, `execute`) resolve the requested path to the location the operating system will actually use, and authorize **that** location. Policy anchors are resolved the same way when the policy is loaded. This matters because a path can name a different file than it reaches: a symlink inside an allowed directory, or a prefix like macOS `/tmp` that is really `/private/tmp`. Without resolving both sides, an explicit `deny` can be stepped over and a broad `allow` wins instead.

`Nitera::check()` is the exception. It is advisory: it matches paths lexically, does no filesystem access, and therefore does not see through those aliases. It can disagree with a guarded operation on an aliased path. Use it to preview a decision, not to enforce one; the guarded methods are the boundary.

Filesystem rules and process scopes use this lookup. Command and host rules keep their existing matching behavior. Preparation adds some load-time work and memory, but no external dependencies or changes to the public API.

If `HOME` changes after loading, Nitera uses the original policy evaluator so home-relative rules follow the current value. Filesystem and process path checks fail closed when `HOME` is unset. See [evaluation of loaded policies](DOCUMENTATION.md#evaluation-of-loaded-policies) for the details.

## The approval flow (`ask` rules)

A rule marked `ask` doesn't resolve to allow or deny on its own, it needs a decision made at runtime by an approval handler.

```rust
use nitera::{ApprovalDecision, Nitera, NiteraRequest};

let nitera = Nitera::load(".nitera")
    .expect("failed to load policy")
    .with_approval_handler(|request: &NiteraRequest| {
        // show the request to a human, a log, a prompt, whatever fits
        println!("Approve: {request}?");
        ApprovalDecision::Approved // or ApprovalDecision::Denied
    });
```

Annotate the parameter as `&NiteraRequest`. Without an explicit type, the closure's inferred signature isn't generic over the request's lifetime and you'll hit `implementation of 'Fn' is not general enough`. Passing a named `fn` item instead of a closure works without the annotation.

`ApprovalHandler` is a plain trait, so a closure or a struct with its own state both work. The handler is only ever consulted for a rule explicitly marked `ask`, it's never given the chance to override a `deny`, and whatever it approves is exactly the operation that was evaluated, nothing about the request can be substituted on the way through.

If no handler is registered, an operation that hits an `ask` rule returns `NiteraOperationError::Ask`, carrying the request that needed a decision, so the failure is loud and specific rather than silently doing nothing:

```rust
match nitera.write(path, content) {
    Ok(()) => println!("write succeeded"),
    Err(err) => println!("{err}"), // e.g. "policy marks `...` as ask, but no approval handler is configured..."
}
```

## Errors

`Nitera::load` returns `NiteraError`:

* `InvalidPolicyFile`: the supplied path is not a `.nitera` policy file. Either the extension has to be `nitera` (`policy.nitera`), or the file has to be named exactly `.nitera`.
* `Io`: the policy file could not be read, or its parent directory could not be canonicalized.
* `Parse`: the `.nitera` file contents could not be parsed.

Every guarded operation (`read`, `write`, `delete`, `execute`, `connect`) returns `NiteraOperationError`, and `Nitera::load` returns `NiteraError`. Both implement `Display` and `std::error::Error`, so they compose with `?` in your own functions.

`Nitera::create` and `Nitera::create_dir` return `NiteraOperationError`. `NiteraOperationError::AlreadyExists(PathBuf)` distinguishes an existing file or directory from a policy denial; policy authorization is always checked first. Other authorization outcomes are returned directly as `NiteraOperationError::Denied`, `NiteraOperationError::Ask`, or `NiteraOperationError::Io`.
## Examples

A runnable demo lives in `examples/playground.rs`, creating files and directories as well as reading, writing, and deleting a file against a real `.nitera` policy, with a terminal prompt for anything marked `ask`.

```bash
cargo run --example playground
```

## Benchmarks

Check cost depends on rule count, pattern shape, and whether the set uses a scan or an index. Broad wildcard patterns can still require scanning many candidates.

The supplied Apple M2 run (16 GB RAM, macOS 27.0, Rust 1.98.1, optimized Cargo bench profile) reports **375 ns median and 500 ns p99 at 1,001 total rules**. Full M2 results, comparison limits, and generated charts are in [`BENCHMARKS.md`](BENCHMARKS.md).

```bash
cargo bench --bench policy_check
```

## Development

```bash
cargo check
cargo test
```

## Current limits

Nitera is a library-level enforcement API. It controls operations performed through the `Nitera` API; it does not prevent an application from directly using `std::fs`, `std::process`, networking APIs, or other libraries to bypass Nitera.

Path authorization is pattern matching over resolved paths, not OS-level sandboxing. Nitera resolves aliases that exist at the moment of the check, but there is still a window between authorizing a path and opening it. An attacker able to replace a directory entry in that window is not defended against; closing that needs descriptor-relative or capability-based access.

Path names are also compared case-sensitively, while macOS and Windows filesystems are usually case-insensitive, and hostnames are compared case-sensitively even though DNS names are not. A `deny` can therefore be stepped over by changing the case of the request. Both are tracked in [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md) as items 2 and 8.

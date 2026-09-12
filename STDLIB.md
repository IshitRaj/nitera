# Rust Standard Library

Nitera currently uses the Rust standard library wherever possible.

## Used so far

* `std::path::{Path, PathBuf, Component}` — filesystem path handling; `Component` specifically for lexically walking and resolving `.`/`..` segments in `normalize_path`.
* `std::fs` — reading, writing, removing, and checking files (`read`, `write`, `read_to_string`, `remove_file`, `exists`) for the library's `read`/`write`/`delete` operations and test fixtures.
* `std::process::{Command, Output}` — spawning and capturing the result of scoped commands in `execute`.
* `std::net::TcpStream` — opening outbound connections in `connect`.
* `std::io::Error` — underlying I/O failures, wrapped in `NiteraOperationError::Io` / `NiteraError::Io`.
* `std::fmt::{Display, Formatter}` — human-readable messages for `NiteraOperationError`, `NiteraError`, `ParseError`, and `NiteraRequest`, so a denied, pending, or parse-failure error prints something actionable instead of a raw Debug dump.
* `std::error::Error` — implemented for `NiteraOperationError`, `NiteraError`, and `ParseError`, so all three compose with `?` and `Box<dyn Error>`. `NiteraOperationError` and `NiteraError` expose their wrapped `io::Error`/`ParseError` through `source()`; `ParseError` has nothing to wrap, so it uses the default `None`.
* `std::sync::Arc` — shared ownership of the optional `dyn ApprovalHandler` on `Nitera`, so every operation call can consult the same handler without owning it.
* `std::env` — the `HOME` environment variable for `~` expansion, `current_dir()` for resolving a path or pattern when no explicit base is given (`PathPattern::matches`, `normalize_runtime_path`), and `temp_dir()` for locating the platform's temp directory in tests instead of hardcoding `/tmp`, since that path differs on macOS.
* `Vec<T>` — storing policy rules.
* `Result<T, E>` — parser, policy-check, and operation error handling.
* `str` methods and iterators — parsing `.nitera` input without a parsing dependency.

## Example-only usage

Used in `examples/playground.rs`, not part of the library itself:

* `std::io::{self, Write}` — reading a y/n answer from stdin and flushing the prompt to stdout for the approval handler.

## Test-only usage

Not part of the library's runtime behavior, used only to keep the test suite isolated when run in parallel:

* `std::sync::atomic::{AtomicU64, Ordering}` — per-process counter for generating unique temp file names, avoiding path collisions between tests.
* `std::time::{SystemTime, UNIX_EPOCH}` — nanosecond component of unique temp file names.
* `std::process::id()` — process-id component of unique temp file names, in case multiple test binaries run concurrently.

## External dependencies

None currently required.

## When stdlib isn't enough

If Nitera needs functionality that Rust's standard library genuinely cannot provide, the reason and chosen solution will be documented here.
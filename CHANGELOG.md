# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Guarded filesystem operations now authorize the location a path actually resolves to, rather than the name that was requested. A symlink inside an allowed directory, or a prefix such as macOS `/tmp` that is really `/private/tmp`, previously let a request step over an explicit `deny` and fall through to a broad `allow`. Policy anchors are resolved to match at load time, so a rule written against one spelling still governs the resolved one. Covers `read`, `write`, `delete`, `create`, `create_dir`, and the working directory of `execute`.
- `delete` resolves only the parent directory and keeps the final component literal, because unlinking a symlink removes the link rather than its target. `read`, `write`, and `create` resolve the target, so a symlinked target is judged by where it lands.
- A **dangling symlink**, whose target does not exist, is now resolved to where it points instead of being authorized as the link itself. Previously a `write` through such a link was checked against the link's location while the bytes landed at the target, so a `deny` on the target directory did not fire. Path resolution walks components for this case; a fully existing path still takes the single `canonicalize` fast path.
- `Nitera::load(".nitera")` now works. The extension check rejected a file named exactly `.nitera`, because `Path::extension` reports no extension for a dotfile, which made the documented quick start fail with `InvalidPolicyFile`. A path is now accepted if its extension is `nitera` or its file name is exactly `.nitera`.
- The `.nitera` parser no longer fails on a run of whitespace between a rule's action and its kind. `allow  read ./a` produced an empty kind and an `unknown filesystem operation: ` error with no name in it. A values list keeps its spacing around commas, since that field is still the rest of the line.

### Changed

- `Nitera::check()` is now documented as advisory. It matches paths lexically, performs no filesystem access, and does not resolve aliases, so it can return a different decision than a guarded method for the same aliased path. It is for previewing a decision, not enforcing one. Its cost is unchanged, since a check still does no filesystem I/O.
- An approval handler now receives a resolved request for `create`, so the request text shows the resolved location rather than the caller's spelling. The handler still cannot substitute a different path, because it returns only a decision about the request it was given.
- `NitraOperationError::AlreadyExists` reports the resolved entry location, which is the entry that was actually found on disk.
- An operation with no rules of any action is now denied before any path resolution, so a policy that does not mention an operation pays no filesystem cost for it.

### Added

- `Nitera` implements `Debug`, so it can be logged or embedded in a struct that derives it. The output shows the policy root and whether an approval handler is registered, and does not reach into the prepared policy or the handler.
- `benches/guarded_operation.rs`, which measures policy load time, `check()`, path resolution, and a full guarded read separately. See `BENCHMARKS.md`.
- CI now runs on `windows-latest` as well as `ubuntu-latest`, and both run formatting and clippy checks. Windows compiles, formats and lints cleanly; path-matching tests fail there, which is tracked as `SECURITY-AUDIT.md` item 3 and does not block other pull requests.
- Loading a policy now resolves each rule's literal anchor, so `Nitera::load` performs filesystem work proportional to the rule count, about 10 microseconds per rule, or roughly 10 ms for a 1,000-rule policy. This is paid once when the policy is loaded. A check still performs no filesystem I/O.

## [1.0.0] - 2026-09-26

### Changed

- Refresh benchmark documentation with the reported Apple M2 results and Python-generated charts.
- Prepare filesystem patterns and process scopes at policy load time. Larger selective sets use prefix lookup, while small and broad sets keep a scan; public policy types and deny/ask/allow precedence are unchanged.
- Reduce repeated path allocation and glob matching work during checks, retaining the existing behavior for missing or changed `HOME` and non-UTF-8 paths.
- Limited the crates.io package contents to essential source files and project metadata using Cargo's include configuration, excluding unnecessary repository files and assets from future package releases.

## [0.1.1] - 2026-09-13

### Fixed

- `Nitera::load()` no longer fails with `Io(NotFound)` when given a bare
  relative filename with no directory component (e.g. `"policy.nitera"`).
  Such paths were resolved correctly as `"./policy.nitera"` or as absolute
  paths, but a bare filename tripped an edge case where `Path::parent()`
  returns an empty path rather than `None`, which was then passed
  unchanged into `canonicalize()`.

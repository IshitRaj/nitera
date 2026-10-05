# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Policy values can now be double-quoted to include literal commas, hashes, and spaces. Quoted values support escaped quotes and backslashes; legacy unquoted values retain their previous interpretation. Malformed unclosed quoted values report their source line.
- Ordinary filesystem and process paths no longer require `HOME`. If `HOME` is unset, a check involving a home-relative request, rule, or process scope fails closed, so an unresolved rule cannot be bypassed by a broad grant.

## [1.0.1] - 2026-09-28

### Fixed

- `Nitera::load(".nitera")` now works. The extension check rejected a file named exactly `.nitera`, because `Path::extension` reports no extension for a dotfile, which made the documented quick start fail with `InvalidPolicyFile`. A path is now accepted if its extension is `nitera` or its file name is exactly `.nitera`.
- The `.nitera` parser no longer fails on a run of whitespace between a rule's action and its kind. `allow  read ./a` produced an empty kind and an `unknown filesystem operation: ` error with no name in it. A values list keeps its spacing around commas, since that field is still the rest of the line.

### Added

- `Nitera` implements `Debug`, so it can be logged or embedded in a struct that derives it. The output shows the policy root and whether an approval handler is registered, and does not reach into the prepared policy or the handler.

### Not in this release

- The resolved-path authorization work is not released yet. Audit items 1 and 18, where a request path and its policy anchor could name the same file through different symlink resolutions, are still unfixed in the published crate. Items 2 and 8, where a case-folded filesystem or hostname can defeat a `deny`, are also still open. See the repository's `SECURITY-AUDIT.md` for the current status.

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

# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

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

# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-09-13

### Fixed

- `Nitera::load()` no longer fails with `Io(NotFound)` when given a bare
  relative filename with no directory component (e.g. `"policy.nitera"`).
  Such paths were resolved correctly as `"./policy.nitera"` or as absolute
  paths, but a bare filename tripped an edge case where `Path::parent()`
  returns an empty path rather than `None`, which was then passed
  unchanged into `canonicalize()`.
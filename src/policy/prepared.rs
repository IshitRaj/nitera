//! Load-time preparation for Nitera's immutable policy. The public, mutable
//! Policy/PathPattern types keep their existing representation and behavior.

use super::model::{PathPattern, Policy};
use super::path::{normalize_pattern, resolve_runtime_path_with_home};
use crate::engine::{Decision, NiteraRequest, Operation, Resource, Target};
use std::ffi::OsString;
use std::path::Path;

enum Tail {
    Exact,
    Subtree,
    Glob(Box<[String]>),
    Never,
}

struct PreparedPath {
    prefix: String,
    tail: Tail,
}

impl PreparedPath {
    fn new(pattern: &PathPattern, base: &Path) -> Self {
        let Ok(normalized) = normalize_pattern(&pattern.0, base) else {
            return Self {
                prefix: String::new(),
                tail: Tail::Never,
            };
        };
        let parts: Vec<_> = normalized.split('/').collect();
        let Some(first_glob) = parts.iter().position(|part| matches!(*part, "*" | "**")) else {
            return Self {
                prefix: normalized,
                tail: Tail::Exact,
            };
        };
        let prefix = parts[..first_glob].join("/");
        let mut suffix = Vec::new();
        for part in &parts[first_glob..] {
            // Adjacent recursive wildcards are equivalent to a single one.
            if *part != "**" || suffix.last().map(String::as_str) != Some("**") {
                suffix.push((*part).to_owned());
            }
        }
        let tail = if suffix.len() == 1 && suffix[0] == "**" {
            Tail::Subtree
        } else {
            Tail::Glob(suffix.into_boxed_slice())
        };
        Self { prefix, tail }
    }

    fn matches(&self, path: &str) -> bool {
        match &self.tail {
            Tail::Never => false,
            Tail::Exact => path == self.prefix,
            tail => {
                // Rules often share a long directory prefix. A cheap comparison
                // at its end can reject a mismatch before comparing that prefix.
                let prefix = self.prefix.as_bytes();
                if let Some(last) = prefix.last()
                    && path.as_bytes().get(prefix.len() - 1) != Some(last)
                {
                    return false;
                }
                let Some(rest) = path.strip_prefix(&self.prefix) else {
                    return false;
                };
                // A literal prefix must end at a component boundary: /app/**
                // includes /app, but must never include /application.
                if !rest.is_empty() && !rest.starts_with('/') {
                    return false;
                }
                match tail {
                    Tail::Subtree => true,
                    Tail::Glob(parts) => match_parts(
                        parts,
                        rest.strip_prefix('/')
                            .into_iter()
                            .flat_map(|rest| rest.split('/')),
                    ),
                    _ => unreachable!(),
                }
            }
        }
    }
}

// Same recursive ** semantics as the original matcher. Iterator clones copy
// cursors only; neither splitting nor backtracking allocates during a check.
fn match_parts(
    mut pattern: &[String],
    mut path: impl DoubleEndedIterator<Item = impl AsRef<str>> + Clone,
) -> bool {
    // Components after the final ** are anchored at the end of the path.
    // Checking them first avoids trying the same suffix at every position.
    while let Some((part, remaining)) = pattern.split_last() {
        if part == "**" {
            break;
        }
        let Some(value) = path.next_back() else {
            return false;
        };
        if part != "*" && part != value.as_ref() {
            return false;
        }
        pattern = remaining;
    }

    while let Some((part, remaining)) = pattern.split_first() {
        if part == "**" {
            if remaining.is_empty() {
                return true;
            }
            loop {
                if match_parts(remaining, path.clone()) {
                    return true;
                }
                if path.next().is_none() {
                    return false;
                }
            }
        }
        let Some(value) = path.next() else {
            return false;
        };
        if part != "*" && part != value.as_ref() {
            return false;
        }
        pattern = remaining;
    }
    path.next().is_none()
}

struct PathRules {
    deny: Vec<PreparedPath>,
    ask: Vec<PreparedPath>,
    allow: Vec<PreparedPath>,
}

fn prepare(patterns: &[PathPattern], base: &Path) -> Vec<PreparedPath> {
    patterns
        .iter()
        .map(|pattern| PreparedPath::new(pattern, base))
        .collect()
}

impl PathRules {
    fn new(deny: &[PathPattern], ask: &[PathPattern], allow: &[PathPattern], base: &Path) -> Self {
        Self {
            deny: prepare(deny, base),
            ask: prepare(ask, base),
            allow: prepare(allow, base),
        }
    }

    fn evaluate(&self, path: &str) -> Decision {
        if self.deny.iter().any(|pattern| pattern.matches(path)) {
            Decision::Deny
        } else if self.ask.iter().any(|pattern| pattern.matches(path)) {
            Decision::Ask
        } else if self.allow.iter().any(|pattern| pattern.matches(path)) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

pub(crate) struct PreparedPolicy {
    // Retain the source for compatibility if HOME changes after loading. This
    // also leaves the public Policy API free to support caller mutations.
    source: Policy,
    home: Option<OsString>,
    read: PathRules,
    write: PathRules,
    delete: PathRules,
    create: PathRules,
    scope: Vec<PreparedPath>,
}

impl PreparedPolicy {
    pub(crate) fn new(source: Policy, base: &Path) -> Self {
        let fs = &source.filesystem;
        Self {
            home: std::env::var_os("HOME"),
            read: PathRules::new(&fs.deny.read, &fs.ask.read, &fs.allow.read, base),
            write: PathRules::new(&fs.deny.write, &fs.ask.write, &fs.allow.write, base),
            delete: PathRules::new(&fs.deny.delete, &fs.ask.delete, &fs.allow.delete, base),
            create: PathRules::new(&fs.deny.create, &fs.ask.create, &fs.allow.create, base),
            scope: prepare(&source.process.scope, base),
            source,
        }
    }

    pub(crate) fn evaluate(&self, request: &NiteraRequest, base: &Path) -> Decision {
        let (path, rules) = match (&request.resource, &request.operation, &request.target) {
            (Resource::Filesystem, Operation::Read, Target::Path(path)) => (path, Some(&self.read)),
            (Resource::Filesystem, Operation::Write, Target::Path(path)) => {
                (path, Some(&self.write))
            }
            (Resource::Filesystem, Operation::Delete, Target::Path(path)) => {
                (path, Some(&self.delete))
            }
            (Resource::Filesystem, Operation::Create, Target::Create { path, .. }) => {
                (path, Some(&self.create))
            }
            (Resource::Process, Operation::Execute, Target::Process { cwd, .. }) => (cwd, None),
            // Network matching already scans borrowed strings without allocation.
            _ => return self.source.evaluate(request, base),
        };

        // The original evaluator does no path work when there are no rules.
        // Preserve that cheap, fail-closed case as well as the populated scan.
        if match rules {
            Some(rules) => rules.deny.is_empty() && rules.ask.is_empty() && rules.allow.is_empty(),
            None => self.scope.is_empty(),
        } {
            return Decision::Deny;
        }

        let home = std::env::var_os("HOME");
        if home != self.home {
            return self.source.evaluate(request, base);
        }
        let Some(home) = home else {
            return Decision::Deny;
        };
        let path = resolve_runtime_path_with_home(path, base, &home);
        let path = path.to_string_lossy();
        if let Some(rules) = rules {
            return rules.evaluate(&path);
        }

        if !self.scope.iter().any(|scope| scope.matches(&path)) {
            return Decision::Deny;
        }
        let Target::Process { command, .. } = &request.target else {
            unreachable!();
        };
        let process = &self.source.process;
        if process.deny.iter().any(|cmd| cmd == command) {
            Decision::Deny
        } else if process.ask.iter().any(|cmd| cmd == command) {
            Decision::Ask
        } else if process.allow.iter().any(|cmd| cmd == command) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_paths_agree_with_original_recursive_matcher() {
        // Exhaust the small component alphabet, including adjacent/middle **,
        // root/empty paths, literal embedded stars and Unicode components.
        fn sequences(alphabet: &[&str], depth: usize) -> Vec<String> {
            let mut all = vec![String::new()];
            let mut level = vec![String::new()];
            for _ in 0..depth {
                level = level
                    .iter()
                    .flat_map(|prefix| alphabet.iter().map(move |part| format!("{prefix}/{part}")))
                    .collect();
                all.extend(level.iter().cloned());
            }
            all
        }
        let paths = sequences(&["a", "b", "é", "x.txt"], 3);
        let patterns = sequences(&["a", "b", "é", "*", "**", "*.txt"], 3);
        let base = Path::new("/base");
        for text in patterns {
            let original = PathPattern(text);
            let prepared = PreparedPath::new(&original, base);
            for path in &paths {
                let resolved = super::super::path::resolve_runtime_path(path, base).unwrap();
                assert_eq!(
                    prepared.matches(&resolved.to_string_lossy()),
                    original.matches_from(Path::new(path), base),
                    "pattern={:?}, path={path:?}",
                    original.0
                );
            }
        }
    }

    #[test]
    fn anchored_glob_suffixes_preserve_recursive_matching() {
        let base = Path::new("/");
        let patterns = [
            "/**/a",
            "/**/*",
            "/**/a/b",
            "/**/*/b",
            "/a/*/**/b",
            "/**/a/**/b",
            "/**/a/**/a/b",
            "/**/*/**/*",
            "/**/**/b",
            "/a/*/b",
            "/**/é/*",
            "/**/*.txt",
            "/**/a/**/b/**/c",
        ];
        let mut paths = vec![String::from("/")];
        let mut level = vec![String::new()];
        for _ in 0..5 {
            level = level
                .iter()
                .flat_map(|prefix| {
                    ["a", "b", "c", "é"]
                        .into_iter()
                        .map(move |part| format!("{prefix}/{part}"))
                })
                .collect();
            paths.extend(level.iter().cloned());
        }
        for text in patterns {
            let original = PathPattern(text.into());
            let prepared = PreparedPath::new(&original, base);
            for path in &paths {
                assert_eq!(
                    prepared.matches(path),
                    original.matches_from(Path::new(path), base),
                    "pattern={text:?}, path={path:?}",
                );
            }
        }
    }
}

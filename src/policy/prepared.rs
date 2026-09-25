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
    deny: PathSet,
    ask: PathSet,
    allow: PathSet,
}

struct PathSet {
    patterns: Vec<PreparedPath>,
    // Empty means the original scan. Otherwise the first rule stays in place
    // and the remaining rules are sorted by prefix.
    prefix_lengths: Box<[usize]>,
}

impl PathSet {
    fn scan(patterns: Vec<PreparedPath>) -> Self {
        Self {
            patterns,
            prefix_lengths: Box::default(),
        }
    }

    fn new(mut patterns: Vec<PreparedPath>) -> Self {
        // Small lists and broad globs are cheaper to scan. Bound the number
        // of prefix searches for policies with many different anchor lengths.
        const MIN_RULES: usize = 64;
        const MIN_PREFIXES: usize = 8;
        const MAX_PREFIX_LENGTHS: usize = 16;
        if patterns.len() < MIN_RULES {
            return Self::scan(patterns);
        }

        let mut prefixes: Vec<_> = patterns
            .iter()
            .map(|pattern| pattern.prefix.as_str())
            .collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        let distinct_prefixes = prefixes.len();
        let mut prefix_lengths: Vec<_> = prefixes.iter().map(|prefix| prefix.len()).collect();
        drop(prefixes);
        prefix_lengths.sort_unstable();
        prefix_lengths.dedup();
        if distinct_prefixes < MIN_PREFIXES || prefix_lengths.len() > MAX_PREFIX_LENGTHS {
            return Self::scan(patterns);
        }

        // Keep the first rule's cheap short circuit. Stable sorting retains the
        // order of the remaining rules sharing an anchor. Actions stay separate.
        patterns[1..].sort_by(|left, right| left.prefix.cmp(&right.prefix));
        Self {
            patterns,
            prefix_lengths: prefix_lengths.into_boxed_slice(),
        }
    }

    fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    #[inline]
    fn matches(&self, path: &str) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        if self.prefix_lengths.is_empty() {
            self.patterns.iter().any(|pattern| pattern.matches(path))
        } else {
            self.patterns[0].matches(path) || self.matches_indexed(path)
        }
    }

    fn matches_indexed(&self, path: &str) -> bool {
        let patterns = &self.patterns[1..];
        for &length in &self.prefix_lengths {
            if length > path.len() {
                break;
            }
            // An exact rule needs the whole path. A glob anchor must end
            // at a component boundary, including the empty anchor.
            if length != path.len() && path.as_bytes()[length] != b'/' {
                continue;
            }
            let Some(prefix) = path.get(..length) else {
                continue;
            };
            let first = patterns.partition_point(|pattern| pattern.prefix.as_str() < prefix);
            for pattern in &patterns[first..] {
                if pattern.prefix != prefix {
                    break;
                }
                // The index only finds candidates; the existing matcher
                // remains responsible for the final decision.
                if pattern.matches(path) {
                    return true;
                }
            }
        }
        false
    }
}

fn prepare(patterns: &[PathPattern], base: &Path) -> PathSet {
    PathSet::new(
        patterns
            .iter()
            .map(|pattern| PreparedPath::new(pattern, base))
            .collect(),
    )
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
        if self.deny.matches(path) {
            Decision::Deny
        } else if self.ask.matches(path) {
            Decision::Ask
        } else if self.allow.matches(path) {
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
    scope: PathSet,
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

        if !self.scope.matches(&path) {
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
    fn indexed_candidates_agree_with_a_full_scan() {
        let base = Path::new("/base");
        let mut patterns = Vec::new();
        for i in 0..128 {
            for suffix in ["/**", "/*/x", "/exact", "/**/last"] {
                patterns.push(PathPattern(format!("./groups/id{i}{suffix}")));
            }
        }
        patterns.extend(
            [
                "/**/private",
                "/**/a/**/last",
                "/",
                "/literal*.txt",
                "/é/東京/**",
            ]
            .into_iter()
            .map(|pattern| PathPattern(pattern.into())),
        );
        let index = prepare(&patterns, base);
        assert!(!index.prefix_lengths.is_empty());
        let scan: Vec<_> = patterns
            .iter()
            .map(|pattern| PreparedPath::new(pattern, base))
            .collect();
        let mut paths = vec![
            "/".to_owned(),
            "/private".into(),
            "/a/b/last".into(),
            "/literal*.txt".into(),
            "/literal.txt".into(),
            "/é/東京/file".into(),
            "/é/東京外/file".into(),
        ];
        for i in 0..132 {
            for suffix in [
                "",
                "/",
                "/x",
                "/a/x",
                "/a/last",
                "/exact",
                "/exact/more",
                "-other",
                "/é",
                "/private",
            ] {
                paths.push(format!("/base/groups/id{i}{suffix}"));
            }
        }
        for path in paths {
            assert_eq!(
                index.matches(&path),
                scan.iter().any(|pattern| pattern.matches(&path)),
                "{path:?}"
            );
        }
    }

    #[test]
    fn broad_and_irregular_sets_keep_the_scan() {
        let base = Path::new("/base");
        let broad: Vec<_> = (0..128)
            .map(|i| PathPattern(format!("/**/file{i}")))
            .collect();
        assert!(prepare(&broad, base).prefix_lengths.is_empty());
        let irregular: Vec<_> = (1..=128)
            .map(|i| PathPattern(format!("/{}/**", "a".repeat(i))))
            .collect();
        assert!(prepare(&irregular, base).prefix_lengths.is_empty());
    }

    #[test]
    fn indexed_process_scopes_preserve_command_decisions() {
        let base = Path::new("/base");
        let mut source = Policy::default();
        source.process.scope = (0..128)
            .map(|i| PathPattern(format!("./group{i}/**")))
            .collect();
        source.process.scope.push(PathPattern("/**/shared".into()));
        source.process.allow = vec!["git".into(), "sh".into(), "blocked".into()];
        source.process.ask = vec!["sh".into()];
        source.process.deny = vec!["blocked".into()];
        let prepared = PreparedPolicy::new(source.clone(), base);
        assert!(!prepared.scope.prefix_lengths.is_empty());
        for i in 0..132 {
            for command in ["git", "sh", "blocked", "unknown"] {
                let request =
                    NiteraRequest::process(command, ["--version"], format!("./group{i}/cwd"));
                assert_eq!(
                    prepared.evaluate(&request, base),
                    source.evaluate(&request, base),
                    "{request:?}"
                );
            }
        }
        let request = NiteraRequest::process("git", ["status"], "/outside/shared");
        assert_eq!(prepared.evaluate(&request, base), Decision::Allow);
        assert_eq!(
            prepared.evaluate(&request, base),
            source.evaluate(&request, base)
        );
    }

    #[test]
    fn indexed_policy_preserves_precedence_and_unanchored_denies() {
        let base = Path::new("/base");
        let mut text = String::from("[filesystem]\n");
        for i in 0..128 {
            text.push_str(&format!("allow read ./group{i}/**\nask read ./group{i}/review/**\ndeny read ./group{i}/secret/**\n"));
        }
        text.push_str("allow read /**\nask read /**/confirm\ndeny read /**/forbidden\n");
        let source = super::super::parse(&text).unwrap();
        let prepared = PreparedPolicy::new(source.clone(), base);
        assert!(!prepared.read.deny.prefix_lengths.is_empty());
        assert!(!prepared.read.ask.prefix_lengths.is_empty());
        assert!(!prepared.read.allow.prefix_lengths.is_empty());
        for i in 0..132 {
            for suffix in [
                "",
                "/file",
                "/secret/data",
                "/review/data",
                "/review/forbidden",
                "/confirm",
                "/secret/../review/file",
                "/é",
            ] {
                let request =
                    NiteraRequest::filesystem(Operation::Read, format!("./group{i}{suffix}"));
                assert_eq!(
                    prepared.evaluate(&request, base),
                    source.evaluate(&request, base),
                    "{request:?}"
                );
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let path = std::ffi::OsString::from_vec(b"/base/group7/secret/invalid-\xff".to_vec());
            let request =
                NiteraRequest::filesystem(Operation::Read, std::path::PathBuf::from(path));
            assert_eq!(prepared.evaluate(&request, base), Decision::Deny);
            assert_eq!(
                prepared.evaluate(&request, base),
                source.evaluate(&request, base)
            );
        }
    }

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

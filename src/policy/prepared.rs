//! Load-time preparation for Nitera's immutable policy. The public, mutable
//! Policy/PathPattern types keep their existing representation and behavior.

use super::model::{PathPattern, Policy};
use super::path::{normalize_pattern, resolve_anchor, resolve_runtime_path_with_home};
use crate::engine::{Decision, NiteraRequest, Operation, Resource, Target};
use std::ffi::OsString;
use std::path::Path;

enum Tail {
    Exact,
    Subtree,
    Glob(Box<[String]>),
    Never,
}

/// Which form of a prepared rule to match a request against.
///
/// `Nitera::check` stays on `Lexical` so it keeps its current cost and
/// touches no filesystem. Guarded operations use `Resolved`, which is the
/// form that matches the location the operating system will actually use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MatchMode {
    Lexical,
    Resolved,
}

struct PreparedPath {
    /// Literal anchor as written, used by the advisory lexical path.
    lexical_prefix: String,
    /// Literal anchor resolved through the filesystem, used when
    /// authorizing a real operation. Resolved once at load time, so a
    /// resolved check still performs no filesystem I/O.
    resolved_prefix: String,
    tail: Tail,
}

impl PreparedPath {
    fn new(pattern: &PathPattern, base: &Path) -> Self {
        let Ok(normalized) = normalize_pattern(&pattern.0, base) else {
            return Self {
                lexical_prefix: String::new(),
                resolved_prefix: String::new(),
                tail: Tail::Never,
            };
        };
        let parts: Vec<_> = normalized.split('/').collect();
        let Some(first_glob) = parts.iter().position(|part| matches!(*part, "*" | "**")) else {
            return Self {
                lexical_prefix: normalized.clone(),
                resolved_prefix: resolve_anchor(&normalized),
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
        Self {
            resolved_prefix: resolve_anchor(&prefix),
            lexical_prefix: prefix,
            tail,
        }
    }

    fn prefix(&self, mode: MatchMode) -> &str {
        match mode {
            MatchMode::Lexical => &self.lexical_prefix,
            MatchMode::Resolved => &self.resolved_prefix,
        }
    }

    fn matches(&self, path: &str, mode: MatchMode) -> bool {
        match &self.tail {
            Tail::Never => false,
            Tail::Exact => path == self.prefix(mode),
            tail => {
                // Rules often share a long directory prefix. A cheap comparison
                // at its end can reject a mismatch before comparing that prefix.
                let prefix_str = self.prefix(mode);
                let owned;
                let prefix = match mode {
                    MatchMode::Lexical => self.lexical_prefix.as_bytes(),
                    MatchMode::Resolved => {
                        owned = self.resolved_prefix.as_bytes();
                        owned
                    }
                };
                if let Some(last) = prefix.last()
                    && path.as_bytes().get(prefix.len() - 1) != Some(last)
                {
                    return false;
                }
                let Some(rest) = path.strip_prefix(prefix_str) else {
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
    /// Absent means this form uses a plain scan. Both views share
    /// `patterns`, so anchoring resolution costs one index array per form
    /// and no extra per-check work.
    lexical: Option<PrefixIndex>,
    resolved: Option<PrefixIndex>,
}

/// A sorted lookup over one prefix form.
///
/// Holds indices into the shared `patterns` list rather than a second copy
/// of the rules, so the resolved and lexical views cost one extra index
/// array each instead of duplicating every pattern.
struct PrefixIndex {
    order: Box<[u32]>,
    lengths: Box<[usize]>,
}

impl PathSet {
    fn new(patterns: Vec<PreparedPath>) -> Self {
        Self {
            lexical: Self::build_index(&patterns, MatchMode::Lexical),
            resolved: Self::build_index(&patterns, MatchMode::Resolved),
            patterns,
        }
    }

    /// Decide whether this rule set is selective enough to index, and build
    /// the ordering if so.
    ///
    /// Small lists and broad globs are cheaper to scan. Bound the number of
    /// prefix searches for policies with many different anchor lengths. The
    /// thresholds are unchanged from the single-form implementation; the
    /// decision is made per form because the two orderings can differ.
    fn build_index(patterns: &[PreparedPath], mode: MatchMode) -> Option<PrefixIndex> {
        const MIN_RULES: usize = 64;
        const MIN_PREFIXES: usize = 8;
        const MAX_PREFIX_LENGTHS: usize = 16;
        if patterns.len() < MIN_RULES {
            return None;
        }

        let mut prefixes: Vec<&str> = patterns.iter().map(|p| p.prefix(mode)).collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        let distinct_prefixes = prefixes.len();
        let mut lengths: Vec<usize> = prefixes.iter().map(|prefix| prefix.len()).collect();
        drop(prefixes);
        lengths.sort_unstable();
        lengths.dedup();
        if distinct_prefixes < MIN_PREFIXES || lengths.len() > MAX_PREFIX_LENGTHS {
            return None;
        }

        let mut order: Vec<u32> = (0..patterns.len() as u32).collect();
        order.sort_by(|&left, &right| {
            patterns[left as usize]
                .prefix(mode)
                .cmp(patterns[right as usize].prefix(mode))
        });

        Some(PrefixIndex {
            order: order.into_boxed_slice(),
            lengths: lengths.into_boxed_slice(),
        })
    }

    fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    #[inline]
    fn matches(&self, path: &str, mode: MatchMode) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        let index = match mode {
            MatchMode::Lexical => &self.lexical,
            MatchMode::Resolved => &self.resolved,
        };
        match index {
            None => self
                .patterns
                .iter()
                .any(|pattern| pattern.matches(path, mode)),
            // Keep the first rule's cheap short circuit before the search.
            Some(_) => self.patterns[0].matches(path, mode) || self.matches_indexed(path, mode),
        }
    }

    fn matches_indexed(&self, path: &str, mode: MatchMode) -> bool {
        let index = match mode {
            MatchMode::Lexical => self.lexical.as_ref().expect("indexed path"),
            MatchMode::Resolved => self.resolved.as_ref().expect("indexed path"),
        };

        for &length in index.lengths.iter() {
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

            let at = |i: u32| &self.patterns[i as usize];
            let first = index
                .order
                .partition_point(|&i| at(i).prefix(mode) < prefix);
            for &i in &index.order[first..] {
                let pattern = at(i);
                if pattern.prefix(mode) != prefix {
                    break;
                }
                // The index only finds candidates; the matcher remains
                // responsible for the final decision.
                if pattern.matches(path, mode) {
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
    /// True when no rule of any action mentions this operation.
    ///
    /// Lets a caller reject before doing any filesystem work, so a policy
    /// that does not mention an operation costs no resolution.
    fn authorizes_nothing(&self) -> bool {
        self.deny.is_empty() && self.ask.is_empty() && self.allow.is_empty()
    }

    fn new(deny: &[PathPattern], ask: &[PathPattern], allow: &[PathPattern], base: &Path) -> Self {
        Self {
            deny: prepare(deny, base),
            ask: prepare(ask, base),
            allow: prepare(allow, base),
        }
    }

    fn evaluate(&self, path: &str, mode: MatchMode) -> Decision {
        if self.deny.matches(path, mode) {
            Decision::Deny
        } else if self.ask.matches(path, mode) {
            Decision::Ask
        } else if self.allow.matches(path, mode) {
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

    /// Whether a filesystem operation has no rules at all, so it is denied
    /// without touching the filesystem.
    pub(crate) fn filesystem_authorizes_nothing(&self, operation: &Operation) -> bool {
        let rules = match operation {
            Operation::Read => &self.read,
            Operation::Write => &self.write,
            Operation::Delete => &self.delete,
            Operation::Create => &self.create,
            _ => return true,
        };
        rules.authorizes_nothing()
    }

    pub(crate) fn evaluate(
        &self,
        request: &NiteraRequest,
        base: &Path,
        mode: MatchMode,
    ) -> Decision {
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
            // Host matching needs no path resolution and stays lexical.
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
            // HOME changed after load, so home-relative rules must be
            // re-resolved. The public evaluator is lexical; that is the
            // documented behavior for this case.
            return self.source.evaluate(request, base);
        }
        let Some(home) = home else {
            return Decision::Deny;
        };
        let path = resolve_runtime_path_with_home(path, base, &home);
        // Rendered in the `/` policy form, matching how anchors are stored.
        let path = super::path::to_policy_string(&path);
        if let Some(rules) = rules {
            return rules.evaluate(&path, mode);
        }

        if !self.scope.matches(&path, mode) {
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
        assert!(index.lexical.is_some() && index.resolved.is_some());
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
                index.matches(&path, MatchMode::Lexical),
                scan.iter()
                    .any(|pattern| pattern.matches(&path, MatchMode::Lexical)),
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
        let broad_set = prepare(&broad, base);
        assert!(broad_set.lexical.is_none() && broad_set.resolved.is_none());
        let irregular: Vec<_> = (1..=128)
            .map(|i| PathPattern(format!("/{}/**", "a".repeat(i))))
            .collect();
        let irregular_set = prepare(&irregular, base);
        assert!(irregular_set.lexical.is_none() && irregular_set.resolved.is_none());
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
        assert!(prepared.scope.lexical.is_some() && prepared.scope.resolved.is_some());
        for i in 0..132 {
            for command in ["git", "sh", "blocked", "unknown"] {
                let request =
                    NiteraRequest::process(command, ["--version"], format!("./group{i}/cwd"));
                assert_eq!(
                    prepared.evaluate(&request, base, MatchMode::Lexical),
                    source.evaluate(&request, base),
                    "{request:?}"
                );
            }
        }
        let request = NiteraRequest::process("git", ["status"], "/outside/shared");
        assert_eq!(
            prepared.evaluate(&request, base, MatchMode::Lexical),
            Decision::Allow
        );
        assert_eq!(
            prepared.evaluate(&request, base, MatchMode::Lexical),
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
        assert!(prepared.read.deny.lexical.is_some());
        assert!(prepared.read.ask.lexical.is_some());
        assert!(prepared.read.allow.lexical.is_some());
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
                    prepared.evaluate(&request, base, MatchMode::Lexical),
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
            assert_eq!(
                prepared.evaluate(&request, base, MatchMode::Lexical),
                Decision::Deny
            );
            assert_eq!(
                prepared.evaluate(&request, base, MatchMode::Lexical),
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
                    // `PreparedPath` holds the `/` policy form, which is what
                    // `evaluate` hands it. Comparing the raw `to_string_lossy`
                    // rendering instead would pass a `\`-separated path on
                    // Windows and never match, for a reason that has nothing to
                    // do with what this test checks.
                    prepared.matches(
                        &super::super::path::to_policy_string(&resolved),
                        MatchMode::Lexical
                    ),
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
                    prepared.matches(path, MatchMode::Lexical),
                    original.matches_from(Path::new(path), base),
                    "pattern={text:?}, path={path:?}",
                );
            }
        }
    }
}

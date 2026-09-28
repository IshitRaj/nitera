use super::{
    model::{HostPattern, PathPattern},
    path::{normalize_pattern, resolve_runtime_path},
};
use std::path::Path;

impl PathPattern {
    /// Match using the current working directory as the base
    /// for relative paths.
    pub fn matches(&self, path: &Path) -> bool {
        let Ok(base) = std::env::current_dir() else {
            return false;
        };

        self.matches_from(path, &base)
    }

    /// Match using an explicit base directory.
    ///
    /// Relative patterns and relative paths are both resolved
    /// against `base`.
    pub fn matches_from(&self, path: &Path, base: &Path) -> bool {
        let Ok(pattern) = normalize_pattern(&self.0, base) else {
            return false;
        };

        let Ok(path) = resolve_runtime_path(path, base) else {
            return false;
        };

        match_path(&pattern, &path)
    }
}

impl HostPattern {
    pub fn matches(&self, host: &str) -> bool {
        host_matches(&self.0, host)
    }
}

fn match_path(pattern: &str, path: &Path) -> bool {
    // The pattern is in the `/` policy form, so the request path has to be
    // rendered the same way, or a Windows request never matches a pattern.
    let path = super::path::to_policy_string(path);

    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();

    match_parts(&pattern_parts, &path_parts)
}

/// Recursive matcher.
fn match_parts(pattern: &[&str], path: &[&str]) -> bool {
    // Both fully consumed at once means match
    if pattern.is_empty() {
        return path.is_empty();
    }

    if pattern[0] == "**" {
        // "**" can swallow ZERO components
        if match_parts(&pattern[1..], path) {
            return true;
        }
        // or ONE MORE component, then try again from the same "**".
        if !path.is_empty() {
            return match_parts(pattern, &path[1..]);
        }

        return false;
    }

    // Any other pattern component needs a real path component to check against
    if path.is_empty() {
        return false;
    }

    if component_matches(pattern[0], path[0]) {
        return match_parts(&pattern[1..], &path[1..]); // consume one from each side, recurse
    }

    false
}

/// Single-segment comparison: "*" matches anything, everything else is literal.
fn component_matches(pattern: &str, value: &str) -> bool {
    pattern == "*" || pattern == value
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.starts_with("*.") {
        return host.ends_with(&pattern[1..]);
    }

    pattern == host
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::path::to_policy_string;
    use std::path::{Path, PathBuf};

    /// A directory that is genuinely absolute on this platform.
    ///
    /// These tests used to hard-code `/home/user/...`, which is only absolute
    /// on Unix. On Windows a `/`-rooted path is drive-relative, so it gets
    /// joined onto the base and can never match, which is why the whole suite
    /// failed there. Every case below builds from a real absolute root and
    /// expresses the pattern in the same `/` policy form the matcher uses.
    fn root() -> PathBuf {
        std::env::temp_dir().join("nitera-matcher-fixture")
    }

    /// The policy string for a path under [`root`].
    fn policy(relative: &str) -> String {
        format!("{}/{}", to_policy_string(&root()), relative)
    }

    fn at(relative: &str) -> PathBuf {
        root().join(relative)
    }

    /// TEMPORARY DIAGNOSTIC, removed once the port is fixed. Prints every
    /// intermediate value so a platform mismatch can be read off the CI log
    /// instead of inferred.
    #[test]
    fn diagnostic_platform_values() {
        use crate::policy::path::{resolve_runtime_path, to_policy_string};

        let cwd = std::env::current_dir().unwrap();
        let base = at("project");
        let home = ensure_home();

        let cases: Vec<(&str, String, PathBuf, PathBuf)> = vec![
            (
                "exact",
                policy("project/file.txt"),
                at("project/file.txt"),
                cwd.clone(),
            ),
            (
                "star",
                policy("projects/*"),
                at("projects/app"),
                cwd.clone(),
            ),
            (
                "rel-dot",
                "./playground/**".into(),
                PathBuf::from("./playground/test.txt"),
                base.clone(),
            ),
            (
                "rel-plain",
                "playground/**".into(),
                PathBuf::from("playground/test.txt"),
                base.clone(),
            ),
            (
                "abs",
                format!("{}/**", to_policy_string(&at("playground"))),
                at("playground/test.txt"),
                base.clone(),
            ),
            (
                "home",
                "~/projects/**".into(),
                PathBuf::from(&home).join("projects/myapp/src/main.rs"),
                at("other-base"),
            ),
        ];

        for (name, pat, req, b) in &cases {
            let norm = normalize_pattern(pat, b);
            let res = resolve_runtime_path(req, b);
            println!("DIAG {name}");
            println!("   base     = {b:?}");
            println!("   base_str = {}", to_policy_string(b));
            println!("   pattern  = {pat:?}");
            println!("   normpat  = {norm:?}");
            println!("   request  = {req:?}");
            println!("   req_str  = {}", to_policy_string(req));
            match &res {
                Ok(r) => {
                    println!("   resolved = {}", to_policy_string(r));
                    println!(
                        "   result   = {}",
                        PathPattern(pat.clone()).matches_from(req, b)
                    );
                    if let Ok(n) = &norm {
                        println!("   rawmatch = {}", match_path(n, r));
                    }
                }
                Err(e) => println!("   resolve_err = {e:?}"),
            }
        }

        println!(
            "DIAG env cwd={cwd:?} temp={:?} HOME={:?} sep={:?} abs={:?}",
            std::env::temp_dir(),
            std::env::var_os("HOME"),
            std::path::MAIN_SEPARATOR,
            at("x").is_absolute()
        );
    }

    #[test]
    fn exact_path_matches() {
        let path = at("project/file.txt");
        let pattern = PathPattern(policy("project/file.txt"));

        assert!(pattern.matches(&path));
    }

    #[test]
    fn different_path_does_not_match() {
        let pattern = PathPattern(policy("project/file.txt"));

        assert!(!pattern.matches(&at("project/other.txt")));
    }

    #[test]
    fn star_matches_single_component() {
        let pattern = PathPattern(policy("projects/*"));

        assert!(pattern.matches(&at("projects/app")));

        assert!(!pattern.matches(&at("projects/app/src")));
    }

    #[test]
    fn double_star_matches_nested_paths() {
        let pattern = PathPattern(policy("projects/**"));

        assert!(pattern.matches(&at("projects/app")));

        assert!(pattern.matches(&at("projects/app/src/main.rs")));
    }

    #[test]
    fn double_star_does_not_match_other_directory() {
        let pattern = PathPattern(policy("projects/**"));

        assert!(!pattern.matches(&at("documents/file.txt")));
    }

    #[test]
    fn relative_pattern_matches_from_base() {
        let pattern = PathPattern("./playground/**".into());
        let base = at("project");

        assert!(pattern.matches_from(Path::new("./playground/test.txt"), &base));
    }

    #[test]
    fn relative_pattern_without_dot_matches_from_base() {
        let pattern = PathPattern("playground/**".into());
        let base = at("project");

        assert!(pattern.matches_from(Path::new("playground/test.txt"), &base));
    }

    #[test]
    fn absolute_pattern_does_not_use_base() {
        let pattern = PathPattern(format!("{}/**", to_policy_string(&at("playground"))));
        let base = at("project");

        assert!(pattern.matches_from(&at("playground/test.txt"), &base));

        assert!(!pattern.matches_from(&at("project/playground/test.txt"), &base));
    }

    /// Returns `HOME`, setting a temporary one if the platform does not
    /// provide it.
    ///
    /// Windows does not set `HOME`. The library only needs it for a
    /// home-relative path, but a test that reads the variable directly would
    /// panic there. Not restored, because every test here wants it and a
    /// process-wide value that matches the platform is not observable.
    fn ensure_home() -> std::ffi::OsString {
        if let Some(existing) = std::env::var_os("HOME") {
            return existing;
        }

        let value = root().join("home-fixture").into_os_string();
        // SAFETY: single-threaded within this test.
        unsafe { std::env::set_var("HOME", &value) };

        value
    }

    #[test]
    fn home_pattern_matches_runtime_path() {
        let pattern = PathPattern("~/projects/**".into());
        let home = ensure_home();

        let path = Path::new(&home)
            .join("projects")
            .join("myapp")
            .join("src")
            .join("main.rs");

        assert!(pattern.matches_from(&path, &at("other-base")));
    }

    #[test]
    fn traversal_is_normalized_before_matching() {
        let pattern = PathPattern("~/projects/**".into());
        let home = ensure_home();

        let path = Path::new(&home)
            .join("projects")
            .join("app")
            .join("..")
            .join("secret.txt");

        assert!(pattern.matches(&path));
    }

    #[test]
    fn host_wildcard_matches_everything() {
        assert!(host_matches("*", "example.com"));
    }

    #[test]
    fn host_subdomain_wildcard_matches_subdomains() {
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "foo.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
    }

    #[test]
    fn exact_host_matches() {
        assert!(host_matches("example.com", "example.com"));
        assert!(!host_matches("example.com", "api.example.com"));
    }
}

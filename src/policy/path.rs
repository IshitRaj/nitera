use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

/// The string form used for policy matching and pattern normalization.
///
/// Policy files are written with `/` separators, so that is the internal
/// form for both patterns and requests. A `Path` renders with the platform
/// separator, so on Windows the backslashes are converted here. This is never
/// done on Unix, where a backslash is a legal character in a filename.
pub fn to_policy_string(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.into_owned()
    }
}

/// Whether a `read_link` failure means "this component is present and is not
/// a symlink", as opposed to "the component could not be inspected".
///
/// Unix reports `EINVAL` for a non-symlink and Windows reports
/// `ERROR_NOT_A_REPARSE_POINT`, which surfaces as `InvalidInput`. Every
/// other kind is an inspection failure and must not be read as a negative
/// answer, because that would silently keep an unresolvable path.
fn is_not_a_symlink(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::InvalidInput
}

/// Strips a leading `~` plus either separator, so a home-relative path is
/// recognized whichever separator the platform uses.
fn strip_home_prefix(text: &str) -> Option<&str> {
    let rest = text.strip_prefix('~')?;
    rest.strip_prefix('/').or_else(|| rest.strip_prefix('\\'))
}

/// Replace a leading `~` with `$HOME`.
pub fn expand_home(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    let path = path.as_ref();

    let home = std::env::var_os("HOME").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME environment variable not set",
        )
    })?;

    Ok(expand_home_with(path, &home).into_owned())
}

fn expand_home_with<'a>(path: &'a Path, home: &'a OsStr) -> Cow<'a, Path> {
    if path == Path::new("~") {
        return Cow::Borrowed(Path::new(home));
    }

    // Detected in string space, so `~/` is recognized on a platform that
    // renders the path with backslashes.
    let path_str = path.to_string_lossy();

    if let Some(stripped) = strip_home_prefix(&path_str) {
        return Cow::Owned(Path::new(home).join(stripped));
    }

    Cow::Borrowed(path)
}

/// Lexically resolve "." and "..", pure component math, no disk access,
/// so it works even for paths that don't exist yet.
pub fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    normalize_components(path.components(), path.as_os_str().len())
}

fn normalize_components<'a>(
    components: impl Iterator<Item = Component<'a>>,
    capacity: usize,
) -> PathBuf {
    let mut normalized = PathBuf::with_capacity(capacity);

    for component in components {
        match component {
            Component::CurDir => {} // "." -> drop

            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                }
            }

            Component::RootDir => {
                normalized.push(Path::new("/"));
            }

            Component::Normal(part) => {
                normalized.push(part); // ordinary segment
            }

            Component::Prefix(prefix) => {
                normalized.push(prefix.as_os_str()); // Windows drive letters, e.g. "C:"
            }
        }
    }

    normalized
}

/// Resolve a runtime path against a base directory.
///
/// Absolute paths remain absolute.
/// Relative paths are resolved against `base`.
/// `~` is resolved against `$HOME`.
pub fn resolve_runtime_path(
    path: impl AsRef<Path>,
    base: impl AsRef<Path>,
) -> std::io::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME environment variable not set",
        )
    })?;

    Ok(resolve_runtime_path_with_home(path.as_ref(), base.as_ref(), &home).into_owned())
}

pub(crate) fn resolve_runtime_path_with_home<'a>(
    path: &'a Path,
    base: &Path,
    home: &OsStr,
) -> Cow<'a, Path> {
    #[cfg(unix)]
    if is_normalized_absolute(path) {
        return Cow::Borrowed(path);
    }

    let expanded = expand_home_with(path, home);
    if expanded.is_absolute() {
        return Cow::Owned(normalize_path(expanded));
    }

    // Unix relative paths append their components to the base. Avoid building
    // an intermediate joined buffer that normalization would immediately copy.
    #[cfg(unix)]
    return Cow::Owned(normalize_components(
        base.components().chain(expanded.components()),
        base.as_os_str().len() + expanded.as_os_str().len() + 1,
    ));

    // Keep platform-specific prefix and rooted-path joining rules on Windows.
    #[cfg(not(unix))]
    Cow::Owned(normalize_path(base.join(expanded)))
}

#[cfg(unix)]
fn is_normalized_absolute(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    bytes == b"/"
        || (bytes.starts_with(b"/")
            && bytes[1..]
                .split(|byte| *byte == b'/')
                .all(|part| !part.is_empty() && part != b"." && part != b".."))
}

/// Re-append `tail` to `base`, nearest component first.
fn prepend_all(base: &Path, tail: &[OsString]) -> PathBuf {
    let mut out = base.to_path_buf();
    for part in tail.iter().rev() {
        out.push(part);
    }
    out
}

/// Resolve symlinks component by component, stopping where the filesystem
/// runs out.
///
/// `canonicalize` is kept as the fast path in `resolve_aliases`, because it
/// is one platform call for the overwhelmingly common case of a path that
/// fully exists. It cannot be used for a path with a missing component
/// though, and a naive "walk up to the nearest existing ancestor and
/// re-append the tail" leaves a trailing symlink unresolved. That is not a
/// cosmetic gap: if the guard authorizes `<dir>/link` while the kernel later
/// follows `link` elsewhere, the check and the syscall again disagree about
/// which resource is touched, which is the bug this whole path exists to
/// prevent.
///
/// So the tail is walked explicitly. Each component is checked with
/// `read_link`:
/// - a symlink is replaced by its target, which is pushed back onto the
///   front of the queue, and a relative target is resolved against the
///   directory holding the link, which is what the kernel does
/// - a missing component ends resolution, because nothing below it can be
///   a symlink. The remainder is appended as written
/// - anything else exists and is not a link, so it is kept
///
/// `..` and `.` are applied to the resolved prefix, so a link target that
/// walks back out is handled the same way the kernel handles it.
fn resolve_components(path: &Path) -> std::io::Result<PathBuf> {
    // A symlink cycle would otherwise spin here. The kernel's own limit for
    // a single path resolution is a reasonable bound to adopt.
    const MAX_SYMLINKS: usize = 40;

    // Steps are kept as kinds rather than plain strings so that the root and
    // Windows prefix markers are never mistaken for ordinary names. They are
    // handed to `PathBuf::push`, which applies the platform's own joining
    // rules for them.
    #[derive(Clone)]
    enum Step {
        RootOrPrefix(OsString),
        Parent,
        Normal(OsString),
    }

    fn step_of(component: Component<'_>) -> Option<Step> {
        match component {
            // A leading `.` carries no meaning and is dropped.
            Component::CurDir => None,
            Component::RootDir | Component::Prefix(_) => {
                Some(Step::RootOrPrefix(component.as_os_str().to_os_string()))
            }
            Component::ParentDir => Some(Step::Parent),
            Component::Normal(name) => Some(Step::Normal(name.to_os_string())),
        }
    }

    // The queue is consumed from the front, so it is filled front to back.
    let mut queue: Vec<Step> = path.components().filter_map(step_of).collect();

    // A relative path is resolved against the current directory up front, so
    // the result is always absolute. Otherwise the value authorized here and
    // the path handed to the syscall could be interpreted against a different
    // working directory, which is the mismatch this whole design avoids.
    let mut resolved = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir()?
    };

    let mut followed = 0usize;
    // Once a component is missing, nothing below it can be a symlink, so the
    // rest is kept as written. The flag is not cleared on `..`: a tail that
    // walks back up is not re-examined, which is the conservative direction.
    let mut past_missing = false;

    while !queue.is_empty() {
        let step = queue.remove(0);

        match step {
            Step::RootOrPrefix(marker) => resolved.push(marker),
            Step::Parent => {
                resolved.pop();
            }
            Step::Normal(name) => {
                if past_missing {
                    resolved.push(name);
                    continue;
                }

                let candidate = resolved.join(&name);
                match std::fs::read_link(&candidate) {
                    // A symlink. Replace it with its target and keep going,
                    // which is what makes a dangling link resolve to where it
                    // points rather than staying as the link itself.
                    Ok(target) => {
                        followed += 1;
                        if followed > MAX_SYMLINKS {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "too many levels of symbolic links",
                            ));
                        }
                        // An absolute target restarts from the root. Starting
                        // from an empty path and letting the target's own
                        // root and prefix components build it keeps Windows
                        // drive and UNC identity intact.
                        if target.is_absolute() {
                            resolved = PathBuf::new();
                        }
                        let spliced: Vec<Step> = target.components().filter_map(step_of).collect();
                        // Forward order: the splice already places these
                        // ahead of whatever is left, so reversing them here
                        // would walk the target backwards.
                        queue.splice(0..0, spliced);
                    }
                    // Missing entirely: nothing below here can resolve.
                    Err(error)
                        if error.kind() == std::io::ErrorKind::NotFound
                            && std::fs::symlink_metadata(&candidate).is_err() =>
                    {
                        resolved.push(name);
                        past_missing = true;
                    }
                    // Exists and is not a symlink, which is the only
                    // remaining reason a component that is present can fail
                    // `read_link`. Any other error means the component could
                    // not be inspected at all: a non-directory in the middle
                    // of the path, a permission failure, or a loop. Treating
                    // those as "not a symlink" would leave an unresolved
                    // name in the path about to be authorized, which is the
                    // mismatch this resolver exists to prevent, so
                    // resolution fails and the operation is refused.
                    Err(error) if is_not_a_symlink(&error) => resolved.push(name),
                    Err(error) => return Err(error),
                }
            }
        }
    }

    Ok(resolved)
}

/// Resolve a path to the location the operating system will actually use,
/// following symlinks in the portion that exists and preserving any
/// components that do not exist yet.
///
/// The fast path is unchanged: a path that exists in full is resolved by one
/// `canonicalize` call, which is what almost every request hits. Only when
/// that fails does the component walk run, and it is what makes a trailing
/// dangling symlink resolve to its real destination instead of being kept as
/// the link itself.
pub fn resolve_aliases(path: &Path) -> std::io::Result<PathBuf> {
    if let Ok(resolved) = path.canonicalize() {
        return Ok(resolved);
    }

    // A bare filename has no directory to resolve against.
    if path
        .parent()
        .is_none_or(|parent| parent.as_os_str().is_empty())
    {
        return Ok(std::env::current_dir()?.join(path));
    }

    resolve_components(path)
}

/// Resolve where a directory entry lives, without following the entry
/// itself.
///
/// `delete` unlinks an entry, so a final symlink is removed rather than
/// followed. Canonicalizing the final component would authorize the
/// link's target instead of the link's own location, so only the parent
/// is resolved and the last component is re-appended literally.
pub fn resolve_entry_location(path: &Path) -> std::io::Result<PathBuf> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok(path.to_path_buf());
    };

    if parent.as_os_str().is_empty() {
        return Ok(prepend_all(
            &std::env::current_dir()?,
            &[name.to_os_string()],
        ));
    }

    Ok(resolve_aliases(parent)?.join(name))
}

/// Resolve a fully literal directory anchor to the location the operating
/// system reports for it.
///
/// A pattern's wildcard components are not filenames and cannot be
/// canonicalized, so callers split a pattern at its first wildcard and
/// resolve only the literal prefix through this function. Resolving anchors
/// and requests the same way is what keeps a policy rule attached to the
/// resource it names: without it, a rule written `/tmp/fixture/**` would
/// not match a request resolved to `/private/tmp/fixture/**`, and a broad
/// `allow` would win over the `deny` the author wrote.
pub fn resolve_anchor(anchor: &str) -> String {
    if anchor.is_empty() || anchor == "/" {
        return anchor.to_string();
    }

    match resolve_aliases(Path::new(anchor)) {
        Ok(resolved) => to_policy_string(&resolved),
        // An anchor that cannot be resolved is kept lexical. Resolution
        // failure must never widen access, and the request side fails closed
        // on a path it cannot resolve, so a lexical anchor here cannot grant
        // access the resolved form would have refused.
        Err(_) => anchor.to_string(),
    }
}

/// Resolve a runtime path against the current working directory.
pub fn normalize_runtime_path(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    resolve_runtime_path(path, cwd)
}

/// Normalize a glob pattern against a base directory.
///
/// Relative patterns are resolved against `base`.
/// Absolute patterns remain absolute.
/// `~` is resolved against `$HOME`.
pub fn normalize_pattern(pattern: &str, base: impl AsRef<Path>) -> std::io::Result<String> {
    // Everything here works in the `/` policy string form rather than on
    // `Path`. Deciding whether a pattern is absolute with `Path::is_absolute`
    // is wrong on Windows, where a `/`-rooted path has a root but no drive and
    // so is not absolute; that made an absolute pattern get joined onto the
    // base. A pattern is absolute if its text starts with a separator, a drive
    // letter, or a UNC `//`.
    let expanded = expand_home(pattern)?;
    let expanded = to_policy_string(&expanded);

    let (anchor, body) = if let Some(rest) = expanded.strip_prefix("\\\\") {
        // UNC: `//server/share/...`
        (Some("//"), rest)
    } else if expanded.len() >= 2
        && expanded.as_bytes()[1] == b':'
        && expanded.as_bytes()[0].is_ascii_alphabetic()
    {
        // Drive: `C:/...`
        (Some(&expanded[..2]), &expanded[2..])
    } else if let Some(rest) = expanded.strip_prefix('/') {
        (Some("/"), rest)
    } else {
        (None, expanded.as_str())
    };

    let base_text = to_policy_string(base.as_ref());
    let body = match anchor {
        Some(_) => body.to_string(),
        None => format!("{}/{}", base_text.trim_end_matches('/'), body),
    };

    let mut result = Vec::new();

    for component in body.split('/') {
        match component {
            "" | "." => {}

            ".." => {
                if let Some(last) = result.last()
                    && *last != "**"
                {
                    result.pop();
                }
            }

            "*" | "**" => {
                result.push(component);
            }

            component => {
                result.push(component);
            }
        }
    }

    let joined = result.join("/");

    // The anchor is reattached in its original form so a drive or UNC prefix
    // survives normalization, while a bare POSIX root keeps its leading `/`.
    Ok(match anchor {
        Some("//") => format!("//{joined}"),
        // A POSIX root needs no re-separator, a drive does.
        Some("/") => format!("/{joined}"),
        Some(drive) => format!("{drive}/{joined}"),
        None => format!("/{joined}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch directory that removes itself when dropped.
    ///
    /// The resolution tests create real symlinks and directories, and a
    /// failing assertion must not leave them behind in the temp directory.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("nitera-path-{tag}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn removes_current_directory() {
        let result = normalize_path("/home/user/./projects/app");

        assert_eq!(result, PathBuf::from("/home/user/projects/app"));
    }

    #[test]
    fn resolves_parent_directory() {
        let result = normalize_path("/home/user/projects/app/../secret");

        assert_eq!(result, PathBuf::from("/home/user/projects/secret"));
    }

    #[test]
    fn resolves_multiple_parent_directories() {
        let result = normalize_path("/home/user/projects/app/../../etc/passwd");

        assert_eq!(result, PathBuf::from("/home/user/etc/passwd"));
    }

    #[test]
    fn traversal_cannot_escape_root() {
        let result = normalize_path("/../../etc/passwd");

        assert_eq!(result, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn expands_home() {
        let result = expand_home("~/projects/file.txt").unwrap();
        let home = std::env::var("HOME").unwrap();

        assert_eq!(result, PathBuf::from(home).join("projects/file.txt"));
    }

    #[test]
    fn relative_path_uses_base() {
        let result = resolve_runtime_path("./playground/test.txt", "/home/user/project").unwrap();

        assert_eq!(
            result,
            PathBuf::from("/home/user/project/playground/test.txt")
        );
    }

    #[test]
    fn absolute_path_ignores_base() {
        let result = resolve_runtime_path("/playground/test.txt", "/home/user/project").unwrap();

        assert_eq!(result, PathBuf::from("/playground/test.txt"));
    }

    #[test]
    fn relative_pattern_uses_base() {
        let result = normalize_pattern("./playground/**", "/home/user/project").unwrap();

        assert_eq!(result, "/home/user/project/playground/**");
    }

    #[test]
    fn absolute_pattern_ignores_base() {
        let result = normalize_pattern("/playground/**", "/home/user/project").unwrap();

        assert_eq!(result, "/playground/**");
    }

    #[test]
    fn pattern_parent_directory_is_normalized() {
        let result = normalize_pattern("/home/user/projects/../other/**", "/ignored").unwrap();

        assert_eq!(result, "/home/user/other/**");
    }

    #[test]
    fn prepared_runtime_paths_match_join_then_normalize() {
        let paths = [
            "",
            ".",
            "..",
            "../..",
            "./a/../b",
            "a//b/",
            "/",
            "//a//b",
            "/a/./b",
            "/a/../../b",
            "/a/b",
            "/a/.hidden",
            "~",
            "~/a/../b",
        ];
        let bases = ["", ".", "base", "base/../other", "/", "/a//b", "/a/../b"];
        let homes = ["", "relative-home", "/home/test", "/home/test/../other"];
        for path in paths {
            for base in bases {
                for home in homes {
                    let path = Path::new(path);
                    let base = Path::new(base);
                    let home = OsStr::new(home);
                    let expanded = expand_home_with(path, home);
                    let expected = normalize_path(base.join(expanded));
                    assert_eq!(
                        resolve_runtime_path_with_home(path, base, home).as_ref(),
                        expected,
                        "path={path:?}, base={base:?}, home={home:?}",
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn normalized_absolute_paths_are_borrowed_without_losing_non_utf8_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(OsStr::from_bytes(b"/private/non-utf8-\xff"));
        let resolved =
            resolve_runtime_path_with_home(path, Path::new("/base"), OsStr::new("/home"));
        assert!(matches!(resolved, Cow::Borrowed(_)));
        assert_eq!(resolved.as_os_str().as_bytes(), path.as_os_str().as_bytes());
        for path in ["/a/", "/a//b", "/a/./b", "/a/../b"] {
            assert!(matches!(
                resolve_runtime_path_with_home(
                    Path::new(path),
                    Path::new("/base"),
                    OsStr::new("/home")
                ),
                Cow::Owned(_),
            ));
        }
    }

    #[test]
    #[cfg(unix)]
    fn resolves_an_existing_symlinked_target() {
        let dir = Scratch::new("symlink");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::fs::write(dir.join("real/leaf"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();

        let resolved = resolve_aliases(&dir.join("link/leaf")).unwrap();
        assert_eq!(resolved, dir.join("real/leaf").canonicalize().unwrap());
    }

    #[test]
    fn resolves_the_deepest_existing_ancestor_and_keeps_the_tail() {
        let dir = Scratch::new("tail");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("a/b")).unwrap();

        // Neither `c` nor `d/e` exists yet, as for create or a new write.
        // `canonicalize` would fail on the whole path, so the expectation
        // is the resolved root plus the untouched tail.
        let resolved = resolve_aliases(&dir.join("a/b/c/d/e")).unwrap();
        assert_eq!(resolved, dir.canonicalize().unwrap().join("a/b/c/d/e"));
    }

    #[test]
    #[cfg(unix)]
    fn entry_location_does_not_follow_a_final_symlink() {
        let dir = Scratch::new("entry");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();

        // Following the final component yields `real`, the link's target.
        // Unlinking acts on the link's own location instead, which is the
        // resolved parent plus the literal final component. Note that
        // `canonicalize` cannot express the link's own location, because
        // canonicalizing a symlink follows it.
        let followed = resolve_aliases(&dir.join("link")).unwrap();
        let location = resolve_entry_location(&dir.join("link")).unwrap();
        assert_eq!(followed, dir.join("real").canonicalize().unwrap());
        assert_eq!(location, dir.canonicalize().unwrap().join("link"));
        assert_ne!(location, followed);
    }

    #[test]
    fn resolution_of_a_bare_filename_uses_the_current_directory() {
        let expected = std::env::current_dir()
            .unwrap()
            .canonicalize()
            .unwrap()
            .join("leaf");
        assert_eq!(resolve_aliases(Path::new("leaf")).unwrap(), expected);
    }

    // ------------------------------------------------------------------
    // Dangling symlink resolution. A symlink whose target does not exist
    // cannot be canonicalized at all, so these exercise the component walk.
    // Authorization must land on the real destination; falling back to the
    // link path would let the check and the syscall disagree.
    // ------------------------------------------------------------------

    /// A symlink pointing at a target that does not exist yet, used as the
    /// final component.
    #[test]
    #[cfg(unix)]
    fn dangling_final_symlink_resolves_to_its_destination() {
        let scratch = Scratch::new("dangling-final");
        let dir = scratch.path();
        std::fs::create_dir_all(dir.join("denied")).unwrap();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        // The target is absent, so the full path cannot be canonicalized.
        std::os::unix::fs::symlink(dir.join("denied/planted"), dir.join("a/link")).unwrap();
        assert!(
            !dir.join("denied/planted").exists(),
            "the target must be absent for this to be the dangling case"
        );

        let resolved = resolve_aliases(&dir.join("a/link")).unwrap();
        assert_eq!(
            resolved,
            dir.canonicalize().unwrap().join("denied/planted"),
            "must resolve to the destination, not the link"
        );
        assert_ne!(
            resolved,
            dir.canonicalize().unwrap().join("a/link"),
            "must not fall back to the link path"
        );
    }

    /// A dangling symlink in the middle of a path, with further components
    /// after it. The whole chain below the link is missing.
    #[test]
    #[cfg(unix)]
    fn dangling_intermediate_symlink_resolves_to_its_destination() {
        let scratch = Scratch::new("dangling-intermediate");
        let dir = scratch.path();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        // `a/link` points at a directory that does not exist.
        std::os::unix::fs::symlink(dir.join("absent"), dir.join("a/link")).unwrap();

        let resolved = resolve_aliases(&dir.join("a/link/child/leaf")).unwrap();
        assert_eq!(
            resolved,
            dir.canonicalize().unwrap().join("absent/child/leaf")
        );
        assert_ne!(
            resolved,
            dir.canonicalize().unwrap().join("a/link/child/leaf"),
            "must not fall back to the link path"
        );
    }

    /// A symlink to a not-yet-existing target, where the caller intends to
    /// create it. Resolution must report where it will be created, which is
    /// what makes a `deny` on the destination fire.
    #[test]
    #[cfg(unix)]
    fn symlink_to_absent_target_reports_creation_site() {
        let scratch = Scratch::new("absent-target");
        let dir = scratch.path();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("dst")).unwrap();
        std::os::unix::fs::symlink(dir.join("dst/created"), dir.join("src/link")).unwrap();

        // Where a create through this link would actually land.
        let resolved = resolve_aliases(&dir.join("src/link")).unwrap();
        assert_eq!(resolved, dir.canonicalize().unwrap().join("dst/created"));
        assert!(!resolved.exists(), "the destination still does not exist");
    }

    /// A chain of symlinks ending in a target that does not exist. Each hop
    /// must be followed, not just the first.
    #[test]
    #[cfg(unix)]
    fn chained_dangling_symlinks_resolve_to_the_final_destination() {
        let scratch = Scratch::new("chained-dangling");
        let dir = scratch.path();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::fs::create_dir_all(dir.join("b")).unwrap();
        // a/one -> b/two, b/two -> c/three, and c does not exist.
        std::os::unix::fs::symlink(dir.join("b/two"), dir.join("a/one")).unwrap();
        std::os::unix::fs::symlink(dir.join("c/three"), dir.join("b/two")).unwrap();

        let resolved = resolve_aliases(&dir.join("a/one")).unwrap();
        assert_eq!(resolved, dir.canonicalize().unwrap().join("c/three"));
    }

    /// A dangling symlink whose target is absolute. The root and prefix are
    /// rebuilt from the target rather than assumed, which is what keeps
    /// Windows drive identity intact.
    #[test]
    #[cfg(unix)]
    fn absolute_dangling_target_restarts_from_the_root() {
        let scratch = Scratch::new("absolute-dangling");
        let dir = scratch.path();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        let target = dir.canonicalize().unwrap().join("nowhere/at/all");
        std::os::unix::fs::symlink(&target, dir.join("a/link")).unwrap();

        let resolved = resolve_aliases(&dir.join("a/link")).unwrap();
        assert_eq!(resolved, target);
        assert!(resolved.is_absolute());
    }

    /// A relative input must resolve to an absolute result even when the tail
    /// is missing. A relative authorized path would be re-resolved against
    /// whatever the working directory is at syscall time.
    #[test]
    fn relative_input_resolves_to_an_absolute_path() {
        let scratch = Scratch::new("relative-input");
        let dir = scratch.path().canonicalize().unwrap();
        std::fs::create_dir_all(dir.join("a")).unwrap();

        // A path relative to the current directory whose tail is missing.
        // The scratch directory above is not involved: `a/missing/...` is
        // taken against the process working directory, which is what a caller
        // passing a relative path means.
        let relative = Path::new("a").join("missing").join("leaf.txt");
        let resolved = resolve_aliases(&relative).unwrap();
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();

        assert!(
            resolved.is_absolute(),
            "a relative request must still resolve to an absolute path, got {resolved:?}"
        );
        assert_eq!(resolved, cwd.join("a/missing/leaf.txt"));
        assert!(!dir.join("a").exists() || resolved.starts_with(&cwd));
    }

    /// A component that cannot be inspected must fail resolution rather than
    /// be kept as an ordinary name.
    ///
    /// Walking through a regular file asks `read_link` about a path whose
    /// parent is not a directory. That is an inspection failure, not an
    /// answer of "not a symlink", and the old code treated it as the latter,
    /// leaving an unresolvable name in the path that was about to be
    /// authorized.
    #[test]
    fn uninspectable_component_fails_resolution() {
        let scratch = Scratch::new("uninspectable");
        let dir = scratch.path();
        // A regular file, so `file/child` cannot be inspected at all.
        std::fs::write(dir.join("file"), b"x").unwrap();

        let result = resolve_aliases(&dir.join("file/child"));
        assert!(
            result.is_err(),
            "walking through a non-directory must fail, got {result:?}"
        );
    }

    /// The same guard for a symlink that cannot be resolved because a
    /// component above it is not a directory.
    #[test]
    fn symlink_under_a_non_directory_is_not_treated_as_a_name() {
        let scratch = Scratch::new("uninspectable-link");
        let dir = scratch.path();
        std::fs::write(dir.join("file"), b"x").unwrap();
        // The link cannot be created under a file, so the path simply cannot
        // be resolved. It must be an error, not a silent pass-through.
        let result = resolve_aliases(&dir.join("file/link/leaf"));
        assert!(result.is_err(), "expected an error, got {result:?}");
    }

    /// A dangling final symlink must resolve to where it points, not stay as
    /// the link itself. `canonicalize` fails here because the target does not
    /// exist, and keeping the link would let a guard authorize one path while
    /// the kernel writes through it to another.
    #[test]
    #[cfg(unix)]
    fn dangling_final_symlink_resolves_to_its_target() {
        let dir = Scratch::new("dangling-final");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("denied")).unwrap();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        // The target does not exist, so canonicalize cannot be used.
        std::os::unix::fs::symlink(dir.join("denied/newfile"), dir.join("a/link")).unwrap();

        let resolved = resolve_aliases(&dir.join("a/link")).unwrap();
        let expected = dir.canonicalize().unwrap().join("denied/newfile");

        assert_ne!(
            resolved,
            dir.canonicalize().unwrap().join("a/link"),
            "the link path itself must not be returned"
        );
        assert_eq!(resolved, expected);
    }

    /// An intermediate symlink followed by a missing final component.
    #[test]
    #[cfg(unix)]
    fn intermediate_symlink_resolves_with_a_missing_tail() {
        let dir = Scratch::new("intermediate");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::fs::create_dir_all(dir.join("a")).unwrap();
        // `a/link` points at `real`, and `leaf` under it does not exist.
        std::os::unix::fs::symlink(dir.join("real"), dir.join("a/link")).unwrap();

        let resolved = resolve_aliases(&dir.join("a/link/leaf/deeper")).unwrap();
        let expected = dir.canonicalize().unwrap().join("real/leaf/deeper");

        assert_eq!(resolved, expected);
    }

    /// A relative symlink target is resolved against the directory holding
    /// the link, exactly as the kernel does.
    #[test]
    #[cfg(unix)]
    fn relative_symlink_target_is_resolved_against_its_directory() {
        let dir = Scratch::new("relative-target");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("here")).unwrap();
        std::fs::create_dir_all(dir.join("there")).unwrap();
        // Points up and across, and the final target does not exist.
        std::os::unix::fs::symlink("../there/missing", dir.join("here/link")).unwrap();

        let resolved = resolve_aliases(&dir.join("here/link")).unwrap();
        assert_eq!(resolved, dir.canonicalize().unwrap().join("there/missing"));
    }

    /// A symlink whose target walks back out with `..`, still missing.
    #[test]
    #[cfg(unix)]
    fn symlink_target_containing_parent_dir_is_resolved() {
        let dir = Scratch::new("parent-target");
        let dir = dir.path();
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::create_dir_all(dir.join("dest")).unwrap();
        std::os::unix::fs::symlink("../../dest/gone", dir.join("a/b/link")).unwrap();

        let resolved = resolve_aliases(&dir.join("a/b/link")).unwrap();
        assert_eq!(resolved, dir.canonicalize().unwrap().join("dest/gone"));
    }

    /// A symlink loop must terminate with an error rather than spinning.
    #[test]
    #[cfg(unix)]
    fn symlink_loop_is_reported_rather_than_hanging() {
        let dir = Scratch::new("loop");
        let dir = dir.path();
        std::os::unix::fs::symlink(dir.join("b"), dir.join("a")).unwrap();
        std::os::unix::fs::symlink(dir.join("a"), dir.join("b")).unwrap();

        // Either the platform's own canonicalize rejects it, or the
        // component walk's hop limit does. Both are acceptable; hanging is not.
        let result = resolve_aliases(&dir.join("a/leaf"));
        assert!(result.is_err(), "a symlink loop must not resolve to a path");
    }

    /// A dangling symlink used as a directory component, where the whole
    /// chain is missing. Resolution stops at the first missing component and
    /// keeps the remainder, rather than discarding the prefix.
    #[test]
    #[cfg(unix)]
    fn missing_prefix_is_kept_verbatim() {
        let dir = Scratch::new("missing-prefix");
        let dir = dir.path();

        let resolved = resolve_aliases(&dir.join("no/such/place/file.txt")).unwrap();
        assert_eq!(
            resolved,
            dir.canonicalize().unwrap().join("no/such/place/file.txt")
        );
    }

    #[test]
    #[cfg(unix)]
    fn non_utf8_components_survive_resolution() {
        use std::os::unix::ffi::OsStringExt;
        let dir = Scratch::new("raw");
        let dir = dir.path();
        let leaf = std::ffi::OsString::from_vec(b"raw-\xff".to_vec());
        let requested = dir.join(&leaf).join("tail");

        let resolved = resolve_aliases(&requested).unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with(Path::new(&leaf).join("tail")));
    }
}

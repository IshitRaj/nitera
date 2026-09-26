use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

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

    let path_str = path.to_string_lossy();

    if let Some(stripped) = path_str.strip_prefix("~/") {
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
    let expanded = expand_home(pattern)?;

    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        base.as_ref().join(expanded)
    };

    let expanded = absolute.to_string_lossy();

    let mut result = Vec::new();

    for component in expanded.split('/') {
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

    Ok(format!("/{}", result.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

use nitera::engine::{Decision, NiteraRequest, Operation};
use nitera::{ApprovalDecision, Nitera, NiteraError, NiteraOperationError};

use std::fs;

fn temp_policy_path() -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "nitera-policy-{}-{}-{}.nitera",
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn unique_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("nitera-{tag}-{}-{n}-{nanos}", std::process::id()))
}

/// True when this platform lets the test create a symlink.
///
/// The symlink regressions need a real link. Off unix they report that they
/// are skipped rather than passing for the wrong reason.
fn symlinks_available() -> bool {
    cfg!(unix)
}

/// The location a create request is authorized against.
///
/// A guarded operation resolves the path before authorizing it, so the
/// request the approval handler receives carries the resolved location
/// rather than the caller's spelling. For a path that does not exist yet
/// that is the resolved parent plus the literal final component.
fn resolved_entry_location(target: &std::path::Path) -> std::path::PathBuf {
    target
        .parent()
        .expect("target has a parent")
        .canonicalize()
        .expect("parent exists")
        .join(target.file_name().expect("target has a name"))
}

/// Writes a one-line policy to a temporary file and loads it.
///
/// Returns the loaded `Nitera` alongside the policy file's path. The
/// caller owns that file and must remove it before returning, so bind
/// the whole tuple rather than discarding the path with `.0`.
/// A scratch directory that removes itself when the guard drops.
///
/// Used by the SECURITY-AUDIT bypass regressions, which need a real
/// directory tree (symlinks, case-insensitive names) rather than a
/// policy string in isolation.
struct Tree {
    path: std::path::PathBuf,
}

impl Tree {
    fn new(tag: &str) -> Self {
        Self::at(&std::env::temp_dir(), tag)
    }

    /// Creates the tree under a specific base directory.
    ///
    /// Item 18 needs this: on macOS the real scenario is a policy rooted at
    /// `/tmp/<dir>`, which canonicalizes to `/private/tmp/<dir>`, and a
    /// request spelled with the `/tmp` alias. Both spellings have to name
    /// the same real directory, so the tree must itself be under `/tmp`.
    fn at(base: &std::path::Path, tag: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = base.join(format!(
            "nitera-tree-{tag}-{}-{n}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn file(&self, relative: &str, contents: &[u8]) -> std::path::PathBuf {
        let target = self.path.join(relative);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, contents).unwrap();
        target
    }

    fn dir(&self, relative: &str) -> std::path::PathBuf {
        let target = self.path.join(relative);
        fs::create_dir_all(&target).unwrap();
        target
    }

    /// Loads a policy written into this tree and returns the handle.
    fn load(&self, policy: &[u8]) -> Nitera {
        let policy_path = self.file("policy.nitera", policy);
        Nitera::load(&policy_path).expect("policy should load")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Whether this volume resolves names that differ only in ASCII case.
///
/// Item 2 cannot exist on a case-sensitive volume, so the regression
/// reports that and returns rather than asserting something untrue.
fn volume_is_case_insensitive(tree: &Tree) -> bool {
    tree.file("CaseProbe", b"x");
    tree.path.join("caseprobe").exists()
}

fn nitera_with_create_rule(action: &str, target: &std::path::Path) -> (Nitera, std::path::PathBuf) {
    let policy_path = temp_policy_path();
    fs::write(
        &policy_path,
        format!("[filesystem]\n{action} create {}\n", target.display()),
    )
    .unwrap();

    (Nitera::load(&policy_path).unwrap(), policy_path)
}

#[test]
fn loads_valid_policy() {
    let path = temp_policy_path();

    fs::write(
        &path,
        r#"
        [filesystem]
        allow read /tmp/**

        [process]
        allow command cargo

        [network]
        allow host api.github.com
        "#,
    )
    .unwrap();

    let result = Nitera::load(&path);

    fs::remove_file(&path).unwrap();

    assert!(result.is_ok());
}

#[test]
fn rejects_missing_policy_file() {
    let path = temp_policy_path();

    let result = Nitera::load(&path);

    assert!(result.is_err());
}

#[test]
fn rejects_invalid_policy() {
    let path = temp_policy_path();

    fs::write(
        &path,
        r#"
        [filesystem]
        something invalid
        "#,
    )
    .unwrap();

    let result = Nitera::load(&path);

    fs::remove_file(&path).unwrap();

    assert!(result.is_err());
}

#[test]
fn reports_missing_file_error() {
    let path = temp_policy_path();

    match Nitera::load(&path) {
        Err(nitera::NiteraError::Io(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        }
        _ => panic!("expected an IO error"),
    }
}

#[test]
fn load_accepts_bare_relative_filename() {
    let dir =
        std::env::temp_dir().join(format!("nitera_bare_filename_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let original_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();

    std::fs::write("policy.nitera", "[filesystem]\nallow read ./data/**\n").unwrap();
    std::fs::create_dir("data").unwrap();

    let result = Nitera::load("policy.nitera");

    std::env::set_current_dir(&original_cwd).unwrap();
    std::fs::remove_dir_all(&dir).ok();

    assert!(result.is_ok());
}

#[test]
fn reports_parse_error_line_and_message() {
    let path = temp_policy_path();

    fs::write(
        &path,
        r#"
        [filesystem]
        allow read /tmp/**
        invalid rule
        "#,
    )
    .unwrap();

    match Nitera::load(&path) {
        Err(nitera::NiteraError::Parse(error)) => {
            assert_eq!(error.line, 4);
            assert_eq!(error.message, "unknown action: invalid");
        }
        _ => panic!("expected a parse error"),
    }

    fs::remove_file(&path).unwrap();
}

#[test]
fn check_allows_allowed_request() {
    let path = temp_policy_path();

    fs::write(
        &path,
        r#"
        [filesystem]
        allow read /tmp/**
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&path).unwrap();

    let request = NiteraRequest::filesystem(Operation::Read, "/tmp/test.txt");

    assert_eq!(nitera.check(&request), Decision::Allow);

    fs::remove_file(&path).unwrap();
}

#[test]
fn check_denies_unmatched_request() {
    let path = temp_policy_path();

    fs::write(
        &path,
        r#"
        [filesystem]
        allow read /tmp/**
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&path).unwrap();

    let request = NiteraRequest::filesystem(Operation::Read, "/etc/passwd");

    assert_eq!(nitera.check(&request), Decision::Deny);

    fs::remove_file(&path).unwrap();
}

#[test]
fn check_returns_ask() {
    let path = temp_policy_path();

    fs::write(
        &path,
        r#"
        [filesystem]
        ask read /tmp/important/**
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&path).unwrap();

    let request = NiteraRequest::filesystem(Operation::Read, "/tmp/important/data.txt");

    assert_eq!(nitera.check(&request), Decision::Ask);

    fs::remove_file(&path).unwrap();
}

#[test]
fn read_allows_allowed_path() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("read-allow-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            allow read {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    // Write the target file directly, bypassing Nitera, so this test
    // only exercises the read path, not write.
    fs::write(&file_path, b"hello from disk").unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    let contents = nitera.read(&file_path).unwrap();

    assert_eq!(contents, b"hello from disk");

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&file_path);
}

#[test]
fn read_denies_disallowed_path() {
    let policy_path = temp_policy_path();
    let file_path = unique_path("read-deny-target.txt");

    // Policy only allows reads under an unrelated scope, so the
    // target path should fall through to the default/deny behavior.
    fs::write(
        &policy_path,
        r#"
        [filesystem]
        allow read /nonexistent-nitera-scope/**
        "#,
    )
    .unwrap();

    fs::write(&file_path, b"should not be readable").unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    let result = nitera.read(&file_path);

    assert!(matches!(result, Err(NiteraOperationError::Denied)));

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&file_path);
}

#[test]
fn read_returns_ask_for_ask_rule() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("read-ask-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            ask read {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    fs::write(&file_path, b"needs confirmation").unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    let result = nitera.read(&file_path);

    assert!(matches!(result, Err(NiteraOperationError::Ask(_))));

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&file_path);
}

#[test]
fn read_propagates_io_error_for_missing_file() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    // Deliberately never created.
    let file_path = unique_path("read-missing-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            allow read {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    let result = nitera.read(&file_path);

    assert!(matches!(result, Err(NiteraOperationError::Io(_))));

    let _ = fs::remove_file(&policy_path);
}

#[test]
fn write_allows_allowed_path() {
    let policy_path = temp_policy_path();
    let dir = std::env::temp_dir();
    let file_path = dir.join("nitera-write-test.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            allow write {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    nitera.write(&file_path, "hello from nitera").unwrap();
    assert_eq!(fs::read_to_string(&file_path).unwrap(), "hello from nitera");

    fs::remove_file(policy_path).unwrap();
    fs::remove_file(file_path).unwrap();
}

#[test]
fn write_denies_disallowed_path() {
    let policy_path = temp_policy_path();
    let dir = std::env::temp_dir();
    let file_path = dir.join("nitera-write-denied.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            deny write {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    let result = nitera.write(&file_path, "should not be written");

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));
    assert!(!file_path.exists());

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn write_returns_ask_for_ask_rule() {
    let policy_path = temp_policy_path();
    let dir = std::env::temp_dir();
    let file_path = dir.join("nitera-write-ask.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            ask write {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let result = nitera.write(&file_path, "should not be written");

    assert!(matches!(result, Err(nitera::NiteraOperationError::Ask(_))));

    assert!(!file_path.exists());

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn write_returns_io_error_when_parent_does_not_exist() {
    let policy_path = temp_policy_path();
    let dir = std::env::temp_dir();

    let missing_dir = dir.join("nitera-missing-parent");
    let file_path = missing_dir.join("file.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            allow write {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let result = nitera.write(&file_path, "hello");

    assert!(matches!(result, Err(nitera::NiteraOperationError::Io(_))));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn delete_allows_allowed_path() {
    let policy_path = temp_policy_path();
    let dir = std::env::temp_dir();
    let file_path = dir.join("nitera-delete-test.txt");

    fs::write(&file_path, "delete me").unwrap();

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            allow delete {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    nitera.delete(&file_path).unwrap();

    assert!(!file_path.exists());

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn delete_denies_disallowed_path() {
    let policy_path = temp_policy_path();
    let dir = std::env::temp_dir();
    let file_path = dir.join("nitera-delete-denied.txt");

    fs::write(&file_path, "keep me").unwrap();

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            deny delete {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    let result = nitera.delete(&file_path);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));
    assert!(file_path.exists());

    fs::remove_file(policy_path).unwrap();
    fs::remove_file(file_path).unwrap();
}

#[test]
fn delete_returns_ask_for_ask_rule() {
    let policy_path = temp_policy_path();
    let dir = std::env::temp_dir();
    let file_path = dir.join("nitera-delete-ask.txt");

    fs::write(&file_path, "keep me").unwrap();

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            ask delete {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    let result = nitera.delete(&file_path);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Ask(_))));
    assert!(file_path.exists());

    fs::remove_file(policy_path).unwrap();
    fs::remove_file(file_path).unwrap();
}

#[test]
fn delete_returns_io_error_when_file_does_not_exist() {
    let policy_path = temp_policy_path();
    let dir = std::env::temp_dir();
    let file_path = dir.join("nitera-delete-missing.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            allow delete {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();
    let result = nitera.delete(&file_path);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Io(_))));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn execute_allows_allowed_command() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [process]
        allow command echo
        allow scope .
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let output = nitera.execute("echo", ["hello"], ".").unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn execute_denies_unknown_command() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [process]
        allow command echo
        allow scope .
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let result = nitera.execute("sh", Vec::<&str>::new(), ".");

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn execute_returns_ask_for_ask_rule() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [process]
        ask command echo
        allow scope .
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let result = nitera.execute("echo", ["hello"], ".");

    assert!(matches!(result, Err(nitera::NiteraOperationError::Ask(_))));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn execute_denies_command_outside_scope() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [process]
        allow command echo
        allow scope ./allowed/**
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let result = nitera.execute("echo", ["hello"], "./");

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn connect_allows_allowed_host() {
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        listener.accept().unwrap();
    });

    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [network]
        allow host 127.0.0.1
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    nitera.connect("127.0.0.1", port).unwrap();

    handle.join().unwrap();
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn connect_denies_denied_host() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [network]
        deny host *
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let result = nitera.connect("127.0.0.1", 1);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn connect_returns_ask_for_ask_rule() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [network]
        ask host 127.0.0.1
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let result = nitera.connect("127.0.0.1", 12345);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Ask(_))));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn connect_deny_overrides_allow() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [network]
        allow host 127.0.0.1
        deny host *
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let result = nitera.connect("127.0.0.1", 12345);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn connect_unknown_host_is_denied() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [network]
        allow host api.github.com
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path).unwrap();

    let result = nitera.connect("example.com", 443);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn example_policy_allows_its_intended_host() {
    // SECURITY-AUDIT item 19: the example policy shipped with `allow host
    // api.github.com` directly above `deny host *`. Deny is checked first,
    // so the allow never applied and the example taught the wrong thing.
    //
    // Checks decisions, not parsing, and opens no socket. Cargo runs
    // integration tests from the crate root, the same relative path
    // `examples/playground.rs` itself uses.
    let nitera =
        Nitera::load("examples/playground.nitera").expect("the shipped example policy should load");

    assert_eq!(
        nitera.check(&NiteraRequest::network("api.github.com", 443)),
        Decision::Allow,
        "the example's only host allow should actually allow"
    );

    // An unmatched host stays denied by default, so removing the
    // catch-all deny must not widen the policy.
    assert_eq!(
        nitera.check(&NiteraRequest::network("example.com", 443)),
        Decision::Deny,
        "removing `deny host *` must not open up unmatched hosts"
    );
}

#[test]
fn read_ask_approved_performs_read() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("read-ask-approved-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            ask read {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    fs::write(&file_path, b"needs confirmation").unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Approved);

    let result = nitera.read(&file_path);

    assert_eq!(result.unwrap(), b"needs confirmation");

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&file_path);
}

#[test]
fn read_ask_denied_returns_denied() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("read-ask-denied-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            ask read {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    fs::write(&file_path, b"needs confirmation").unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Denied);

    let result = nitera.read(&file_path);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&file_path);
}

#[test]
fn write_ask_approved_performs_write() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("write-ask-approved-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            ask write {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Approved);

    nitera.write(&file_path, b"hello").unwrap();

    assert_eq!(fs::read(&file_path).unwrap(), b"hello");

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&file_path);
}

#[test]
fn write_ask_denied_returns_denied() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("write-ask-denied-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            ask write {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Denied);

    let result = nitera.write(&file_path, b"hello");

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));
    assert!(!file_path.exists());

    let _ = fs::remove_file(&policy_path);
}

#[test]
fn delete_ask_approved_performs_delete() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("delete-ask-approved-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            ask delete {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    fs::write(&file_path, b"soon gone").unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Approved);

    nitera.delete(&file_path).unwrap();

    assert!(!file_path.exists());

    let _ = fs::remove_file(&policy_path);
}

#[test]
fn delete_ask_denied_returns_denied() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("delete-ask-denied-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            ask delete {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    fs::write(&file_path, b"stays put").unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Denied);

    let result = nitera.delete(&file_path);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));
    assert!(file_path.exists());

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&file_path);
}

#[test]
fn execute_ask_approved_runs_command() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [process]
        ask command echo
        allow scope .
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Approved);

    let output = nitera.execute("echo", ["hello"], ".").unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn execute_ask_denied_returns_denied() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [process]
        ask command echo
        allow scope .
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Denied);

    let result = nitera.execute("echo", ["hello"], ".");

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn connect_ask_approved_opens_connection() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [network]
        ask host 127.0.0.1
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Approved);

    let result = nitera.connect("127.0.0.1", port);

    assert!(result.is_ok());

    drop(listener);
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn connect_ask_denied_returns_denied() {
    let policy_path = temp_policy_path();

    fs::write(
        &policy_path,
        r#"
        [network]
        ask host 127.0.0.1
        "#,
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Denied);

    let result = nitera.connect("127.0.0.1", 12345);

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));

    fs::remove_file(policy_path).unwrap();
}

#[test]
fn write_deny_rule_overrides_approving_handler() {
    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("write-deny-overrides-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            deny write {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera = Nitera::load(&policy_path)
        .unwrap()
        .with_approval_handler(|_: &nitera::NiteraRequest| nitera::ApprovalDecision::Approved);

    let result = nitera.write(&file_path, b"hello");

    assert!(matches!(result, Err(nitera::NiteraOperationError::Denied)));
    assert!(!file_path.exists());

    let _ = fs::remove_file(&policy_path);
}

#[test]
fn write_allow_rule_never_invokes_handler() {
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    let dir = std::env::temp_dir();
    let policy_path = temp_policy_path();
    let file_path = unique_path("write-allow-no-handler-target.txt");

    fs::write(
        &policy_path,
        format!(
            r#"
            [filesystem]
            allow write {}/**
            "#,
            dir.display()
        ),
    )
    .unwrap();

    let nitera =
        Nitera::load(&policy_path)
            .unwrap()
            .with_approval_handler(|_: &nitera::NiteraRequest| {
                CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                nitera::ApprovalDecision::Approved
            });

    nitera.write(&file_path, b"hello").unwrap();

    assert_eq!(CALLS.load(std::sync::atomic::Ordering::SeqCst), 0);

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&file_path);
}

#[test]
fn rejects_non_nitera_policy_file() {
    let path = std::env::temp_dir().join("nitera-invalid-policy.txt");

    fs::write(&path, "[filesystem]\nallow read ./playground/**").unwrap();

    let result = Nitera::load(&path);

    assert!(matches!(result, Err(NiteraError::InvalidPolicyFile)));

    fs::remove_file(path).unwrap();
}

#[test]
fn accepts_nitera_policy_file() {
    let path = std::env::temp_dir().join("nitera-valid-policy.nitera");

    fs::write(&path, "[filesystem]\nallow read ./playground/**").unwrap();

    assert!(Nitera::load(&path).is_ok());

    fs::remove_file(path).unwrap();
}

#[test]
fn create_allow_rule_creates_a_file_from_str() {
    let target = unique_path("create-file-allowed.txt");
    let (nitera, policy_path) = nitera_with_create_rule("allow", &target);

    nitera.create(&target, "created file").unwrap();

    assert_eq!(fs::read(&target).unwrap(), b"created file");
    fs::remove_file(target).unwrap();
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_allow_rule_creates_a_directory() {
    let target = unique_path("create-directory-allowed");
    let (nitera, policy_path) = nitera_with_create_rule("allow", &target);

    nitera.create_dir(&target).unwrap();

    assert!(target.is_dir());
    fs::remove_dir(target).unwrap();
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_deny_rule_blocks_a_file() {
    let target = unique_path("create-file-denied.txt");
    let (nitera, policy_path) = nitera_with_create_rule("deny", &target);

    let result = nitera.create(&target, b"blocked");

    assert!(matches!(result, Err(NiteraOperationError::Denied)));
    assert!(!target.exists());
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_deny_rule_blocks_a_directory() {
    let target = unique_path("create-directory-denied");
    let (nitera, policy_path) = nitera_with_create_rule("deny", &target);

    let result = nitera.create_dir(&target);

    assert!(matches!(result, Err(NiteraOperationError::Denied)));
    assert!(!target.exists());
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_ask_approved_creates_a_file_and_labels_the_request() {
    let target = unique_path("create-file-asked.txt");
    let expected_request = format!("Create file {}", resolved_entry_location(&target).display());
    let (nitera, policy_path) = nitera_with_create_rule("ask", &target);
    let nitera = nitera.with_approval_handler(move |request: &NiteraRequest| {
        assert_eq!(request.to_string(), expected_request);
        ApprovalDecision::Approved
    });

    nitera.create(&target, b"approved").unwrap();

    assert_eq!(fs::read(&target).unwrap(), b"approved");
    fs::remove_file(target).unwrap();
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_ask_approved_creates_a_directory_and_labels_the_request() {
    let target = unique_path("create-directory-asked");
    let expected_request = format!(
        "Create directory {}",
        resolved_entry_location(&target).display()
    );
    let (nitera, policy_path) = nitera_with_create_rule("ask", &target);
    let nitera = nitera.with_approval_handler(move |request: &NiteraRequest| {
        assert_eq!(request.to_string(), expected_request);
        ApprovalDecision::Approved
    });

    nitera.create_dir(&target).unwrap();

    assert!(target.is_dir());
    fs::remove_dir(target).unwrap();
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_ask_denied_blocks_a_file() {
    let target = unique_path("create-file-ask-denied.txt");
    let (nitera, policy_path) = nitera_with_create_rule("ask", &target);
    let nitera = nitera.with_approval_handler(|_: &NiteraRequest| ApprovalDecision::Denied);

    let result = nitera.create(&target, b"blocked");

    assert!(matches!(result, Err(NiteraOperationError::Denied)));
    assert!(!target.exists());
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_ask_denied_blocks_a_directory() {
    let target = unique_path("create-directory-ask-denied");
    let (nitera, policy_path) = nitera_with_create_rule("ask", &target);
    let nitera = nitera.with_approval_handler(|_: &NiteraRequest| ApprovalDecision::Denied);

    let result = nitera.create_dir(&target);

    assert!(matches!(result, Err(NiteraOperationError::Denied)));
    assert!(!target.exists());
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_reports_already_exists_for_an_existing_file_after_authorization() {
    let target = unique_path("create-existing-file.txt");
    fs::write(&target, b"already here").unwrap();
    let (nitera, policy_path) = nitera_with_create_rule("allow", &target);

    let result = nitera.create(&target, b"new contents");

    // The reported path is the resolved entry location, which is the entry
    // that was actually found on disk.
    assert!(
        matches!(result, Err(NiteraOperationError::AlreadyExists(path)) if path ==
            resolved_entry_location(&target))
    );
    fs::remove_file(target).unwrap();
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_denial_takes_priority_over_an_existing_target() {
    let target = unique_path("create-denied-existing-file.txt");
    fs::write(&target, b"already here").unwrap();
    let (nitera, policy_path) = nitera_with_create_rule("deny", &target);

    let result = nitera.create(&target, b"new contents");

    assert!(matches!(result, Err(NiteraOperationError::Denied)));
    fs::remove_file(target).unwrap();
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_reports_already_exists_for_an_existing_directory_after_authorization() {
    let target = unique_path("create-existing-directory");
    fs::create_dir(&target).unwrap();
    let (nitera, policy_path) = nitera_with_create_rule("allow", &target);

    let result = nitera.create_dir(&target);

    // The reported path is the resolved entry location, which is the entry
    // that was actually found on disk.
    assert!(
        matches!(result, Err(NiteraOperationError::AlreadyExists(path)) if path ==
            resolved_entry_location(&target))
    );
    fs::remove_dir(target).unwrap();
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn create_accepts_empty_content() {
    let target = unique_path("create-empty-file.txt");
    let (nitera, policy_path) = nitera_with_create_rule("allow", &target);

    nitera.create(&target, "").unwrap();

    assert!(fs::read(&target).unwrap().is_empty());
    fs::remove_file(target).unwrap();
    fs::remove_file(policy_path).unwrap();
}

#[test]
fn loads_policy_from_bare_dotfile_named_nitera() {
    // `Path::new(".nitera").extension()` is `None`, because a leading dot
    // reads as a hidden-file marker rather than a separator. The README
    // quick start uses exactly this filename, so it has to load.
    let dir = unique_path("dotfile-policy");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(".nitera");

    fs::write(&path, "[filesystem]\nallow read ./**\n").unwrap();

    let nitera = Nitera::load(&path).expect("a file named exactly .nitera should load");

    assert_eq!(
        nitera.check(&NiteraRequest::filesystem(Operation::Read, "./x.txt")),
        Decision::Allow
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn still_rejects_other_extensions() {
    let dir = unique_path("wrong-ext");
    fs::create_dir_all(&dir).unwrap();

    // `policy.nitersa` is a near-miss extension, not the dotfile form.
    for name in ["policy.nitersa", "policy.txt", "policy", ".nitera.bak"] {
        let path = dir.join(name);
        fs::write(&path, "[filesystem]\n").unwrap();
        assert!(
            matches!(Nitera::load(&path), Err(NiteraError::InvalidPolicyFile)),
            "{name} should be rejected"
        );
    }

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn nitera_is_debug_formattable() {
    let (nitera, policy_path) = nitera_with_create_rule("allow", &unique_path("debug.txt"));

    let rendered = format!("{nitera:?}");
    assert!(rendered.starts_with("Nitera"), "{rendered}");
    assert!(rendered.contains("root"), "{rendered}");
    assert!(rendered.contains("approval_handler"), "{rendered}");
    assert!(rendered.contains("none"), "{rendered}");

    let (unhandled, handler_policy_path) =
        nitera_with_create_rule("allow", &unique_path("debug2.txt"));
    let with_handler =
        unhandled.with_approval_handler(|_: &NiteraRequest| ApprovalDecision::Approved);
    assert!(format!("{with_handler:?}").contains("registered"));

    fs::remove_file(policy_path).unwrap();
    fs::remove_file(handler_policy_path).unwrap();
}

// ---------------------------------------------------------------------------
// SECURITY-AUDIT bypass regressions, items 1, 2, 8, and 18.
//
// Written before the fixes, so each one fails against current `main`. They
// are `#[ignore]`d for that reason: `main` requires `cargo test` to pass,
// so a deliberately failing test cannot land until its fix does. Drop the
// attribute when the item is fixed and the test becomes a permanent guard.
//
// Run them with:
//
//     cargo test --test nitera -- --ignored audit
//
// Each pairs the bypass with a control assertion. Without the control a
// test could pass simply by denying everything, hiding the defect rather
// than catching it.
// ---------------------------------------------------------------------------

/// Item 1: a symlink inside an allowed directory reaches a denied file.
#[test]
fn audit_item1_symlink_defeats_explicit_deny() {
    let tree = Tree::new("item1");
    tree.file("Secrets/key", b"SYMLINK PAYLOAD");
    let n = tree.load(b"[filesystem]\nallow read ./allowed/**\ndeny read ./Secrets/**\n");

    // Create only the parent; the link itself must not exist yet.
    tree.dir("allowed");
    if !symlinks_available() {
        eprintln!("reported as skipped: symlinks are not creatable on this platform");
        return;
    }
    std::os::unix::fs::symlink(tree.path.join("Secrets"), tree.path.join("allowed/escape"))
        .unwrap();

    // Control: the direct spelling is denied, so the policy is loaded and
    // the deny rule is present.
    assert_eq!(
        n.check(&NiteraRequest::filesystem(Operation::Read, "./Secrets/key")),
        Decision::Deny,
        "control: the direct path must be denied"
    );
    // The guarded operation is the security boundary: it authorizes the
    // resolved location, so a symlink cannot reach a denied file. The error
    // variant is asserted rather than `is_err`, so a read that failed for an
    // unrelated reason cannot pass this test.
    assert!(
        matches!(
            n.read("./allowed/escape/key"),
            Err(NiteraOperationError::Denied)
        ),
        "item 1: the guarded read reached the denied file through a symlink"
    );

    // `check` stays lexical and advisory, so it still reports Allow here.
    // The split is deliberate and pinned by this assertion so it cannot
    // change by accident: a caller must not treat `check` as enforcement.
    assert_eq!(
        n.check(&NiteraRequest::filesystem(
            Operation::Read,
            "./allowed/escape/key"
        )),
        Decision::Allow,
        "check is advisory and lexical; it does not resolve aliases"
    );
}

/// Item 1 through the prepared index, which selects candidates with its
/// own byte-sensitive comparisons in `prepared.rs`.
#[test]
fn audit_item1_symlink_defeats_deny_with_index() {
    let tree = Tree::new("item1-index");
    tree.file("Secrets/key", b"SYMLINK PAYLOAD");

    let mut policy = String::from("[filesystem]\n");
    for i in 0..70 {
        policy.push_str(&format!("allow read ./group{i}/**\n"));
    }
    policy.push_str("allow read ./allowed/**\ndeny read ./Secrets/**\n");
    let n = tree.load(policy.as_bytes());

    // Create only the parent; the link itself must not exist yet.
    tree.dir("allowed");
    if !symlinks_available() {
        eprintln!("reported as skipped: symlinks are not creatable on this platform");
        return;
    }
    std::os::unix::fs::symlink(tree.path.join("Secrets"), tree.path.join("allowed/escape"))
        .unwrap();

    assert_eq!(
        n.check(&NiteraRequest::filesystem(Operation::Read, "./Secrets/key")),
        Decision::Deny
    );
    assert!(
        matches!(
            n.read("./allowed/escape/key"),
            Err(NiteraOperationError::Denied)
        ),
        "item 1: the guarded read reached the denied file with the index engaged"
    );
}

/// Item 2: a mis-cased path skips a case-sensitive deny on a
/// case-insensitive volume. No symlink is needed.
#[test]
#[ignore = "item 2 open: mis-cased path skips a case-sensitive deny"]
fn audit_item2_miscased_path_defeats_deny() {
    let tree = Tree::new("item2");
    if !volume_is_case_insensitive(&tree) {
        eprintln!("reported as skipped: volume is case-sensitive, item 2 cannot apply here");
        return;
    }
    tree.file("Secrets/key", b"CASE PAYLOAD");
    let n = tree.load(b"[filesystem]\ndeny read ./Secrets/**\nallow read ./**\n");

    // Control: correctly cased request is denied.
    assert_eq!(
        n.check(&NiteraRequest::filesystem(Operation::Read, "./Secrets/key")),
        Decision::Deny,
        "control: the correctly cased path must be denied"
    );

    assert_eq!(
        n.check(&NiteraRequest::filesystem(Operation::Read, "./secrets/key")),
        Decision::Deny,
        "item 2: a mis-cased path skipped the deny"
    );
    assert!(
        matches!(n.read("./secrets/key"), Err(NiteraOperationError::Denied)),
        "item 2: the guarded read reached the denied file"
    );
}

/// Item 2 through the prepared index.
#[test]
#[ignore = "item 2 open: mis-cased path skips the deny once the index engages"]
fn audit_item2_miscased_path_defeats_deny_with_index() {
    let tree = Tree::new("item2-index");
    if !volume_is_case_insensitive(&tree) {
        eprintln!("reported as skipped: volume is case-sensitive, item 2 cannot apply here");
        return;
    }
    tree.file("Secrets/key", b"CASE PAYLOAD");

    let mut policy = String::from("[filesystem]\n");
    for i in 0..70 {
        policy.push_str(&format!("allow read ./group{i}/**\n"));
    }
    policy.push_str("deny read ./Secrets/**\nallow read ./**\n");
    let n = tree.load(policy.as_bytes());

    assert_eq!(
        n.check(&NiteraRequest::filesystem(Operation::Read, "./Secrets/key")),
        Decision::Deny
    );
    assert_eq!(
        n.check(&NiteraRequest::filesystem(Operation::Read, "./secrets/key")),
        Decision::Deny,
        "item 2: bypass survives the indexed lookup"
    );
}

/// Item 18: a policy root reached through an alias, such as macOS
/// `/tmp`, skips a deny anchored at the canonical root.
#[test]
fn audit_item18_alias_defeats_deny() {
    if !cfg!(target_os = "macos") {
        eprintln!("reported as skipped: the /tmp alias only exists on macOS");
        return;
    }
    // The tree must live under /tmp, because the scenario is a policy rooted
    // at /tmp/<dir> with a request spelled using the /tmp alias. A tree under
    // the default temp dir would make the alias name a directory that does
    // not exist, and the read would fail with Io rather than Deny, which
    // would let this test pass without proving anything.
    let tree = Tree::at(std::path::Path::new("/tmp"), "item18");
    tree.file("key", b"ALIAS PAYLOAD");
    // The audit's own reproducer.
    let n = tree.load(b"[filesystem]\nallow read /**\ndeny read ./**\n");

    // Control: the relative spelling is denied by the canonical-root deny.
    assert!(
        matches!(n.read("./key"), Err(NiteraOperationError::Denied)),
        "control: the relative path must be denied"
    );

    let alias = std::path::Path::new("/tmp")
        .join(tree.path.file_name().unwrap())
        .join("key");

    // Sanity: the alias spelling must name the same real file, and must
    // differ as a string from the canonical one. Without both of these the
    // assertions below would be meaningless.
    assert!(
        alias.exists(),
        "the /tmp alias must resolve to the same file, or this proves nothing"
    );
    assert_ne!(
        alias,
        alias.canonicalize().unwrap(),
        "the /tmp spelling must differ from its canonical form, or there is no alias to defeat"
    );

    assert!(
        matches!(n.read(&alias), Err(NiteraOperationError::Denied)),
        "item 18: the guarded read reached the denied file through the alias"
    );
    assert_eq!(
        n.check(&NiteraRequest::filesystem(Operation::Read, &alias)),
        Decision::Allow,
        "check is advisory and lexical; the alias is not resolved there"
    );
}

/// Item 8: hostnames are matched byte-case-sensitively, so a mis-cased
/// host skips a deny on an allow-listed network.
#[test]
#[ignore = "item 8 open: a mis-cased hostname skips the deny"]
fn audit_item8_miscased_host_defeats_deny() {
    let tree = Tree::new("item8");
    let n = tree.load(b"[network]\ndeny host api.github.com\nallow host *\n");

    // Control: the correctly cased host is denied.
    assert_eq!(
        n.check(&NiteraRequest::network("api.github.com", 443)),
        Decision::Deny,
        "control: the correctly cased host must be denied"
    );

    for host in ["API.GITHUB.COM", "Api.GitHub.Com"] {
        assert_eq!(
            n.check(&NiteraRequest::network(host, 443)),
            Decision::Deny,
            "item 8: mis-cased host {host} skipped the deny"
        );
    }

    // Control in the other direction: an unrelated host stays allowed, so
    // this cannot pass by denying everything.
    assert_eq!(
        n.check(&NiteraRequest::network("example.com", 443)),
        Decision::Allow,
        "control: an unrelated host must stay allowed"
    );
}

// ---------------------------------------------------------------------------
// Guards on the resolved-authorization change. These do not test a bypass;
// they test that resolving did not quietly widen or narrow access.
// ---------------------------------------------------------------------------

/// A deny written against an absolute path must still fire when the caller
/// asks for that path through a symlinked directory inside an allowed tree.
///
/// This is the fail-open the audit warned about: if the request were
/// resolved but the deny anchor were not, the deny would stop matching and
/// a broad allow would win.
#[test]
fn deny_anchor_survives_a_symlinked_request_path() {
    let tree = Tree::new("guard-anchor");
    tree.file("Secrets/key", b"PAYLOAD");
    // The deny anchor is absolute and in the resolved spelling.
    // Canonicalize the anchor exactly as a policy author would write it,
    // then add the separator explicitly: `display()` has no trailing slash.
    let anchor = tree.path.canonicalize().unwrap();
    let deny = format!("deny read {}/Secrets/**\n", anchor.display());
    let policy = format!("[filesystem]\nallow read ./**\n{deny}");
    let n = tree.load(policy.as_bytes());

    tree.dir("allowed");
    if !symlinks_available() {
        eprintln!("reported as skipped: symlinks are not creatable on this platform");
        return;
    }
    std::os::unix::fs::symlink(tree.path.join("Secrets"), tree.path.join("allowed/escape"))
        .unwrap();

    let r = n.read("./allowed/escape/key");
    assert!(
        matches!(r, Err(NiteraOperationError::Denied)),
        "an absolute deny anchor must survive a symlinked request path"
    );
}

/// An operation with no rules must be denied without any filesystem work,
/// including when the path could not be resolved at all.
#[test]
fn unmentioned_operation_is_denied_and_never_resolves() {
    let tree = Tree::new("guard-empty");
    // Only read rules. Write, delete, and create are all unmentioned.
    let n = tree.load(b"[filesystem]\nallow read ./**\n");

    // A path that does not exist and whose parent does not either, so any
    // resolution attempt would have to walk and fail.
    let missing = tree.path.join("no/such/parent/file.txt");

    assert!(matches!(
        n.write(&missing, b"x"),
        Err(NiteraOperationError::Denied)
    ));
    assert!(matches!(
        n.delete(&missing),
        Err(NiteraOperationError::Denied)
    ));
    assert!(matches!(
        n.create(&missing, b"x"),
        Err(NiteraOperationError::Denied)
    ));
    assert!(matches!(
        n.create_dir(&missing),
        Err(NiteraOperationError::Denied)
    ));
}

/// An allow-list that does not cover the resolved location must still deny.
///
/// Guards against resolution accidentally reinterpreting a rule as a
/// broader match.
#[test]
fn allow_outside_the_resolved_tree_stays_denied() {
    let tree = Tree::new("guard-outside");
    let outside = tree.dir("outside");
    tree.file("outside/secret", b"SECRET");

    let n = tree.load(b"[filesystem]\nallow read ./inside/**\n");

    // `matches!` cannot carry a message, so the reasons are asserted first.
    assert!(
        matches!(
            n.read(outside.join("secret")),
            Err(NiteraOperationError::Denied)
        ),
        "an absolute path outside the allowed tree must stay denied"
    );
    assert!(
        matches!(
            n.read("./outside/secret"),
            Err(NiteraOperationError::Denied)
        ),
        "a relative path outside the allowed tree must stay denied"
    );
}

/// `delete` must judge a symlink by its own location, not its target.
///
/// Removing a symlink is not the same operation as deleting what it points
/// at, so the target being inside an allowed tree must not make the link
/// itself deletable, and the reverse must also hold.
#[test]
fn delete_judges_a_symlink_by_its_own_location() {
    let tree = Tree::new("guard-delete");
    tree.file("target/keep", b"KEEP");
    tree.dir("links");

    if !symlinks_available() {
        eprintln!("reported as skipped: symlinks are not creatable on this platform");
        return;
    }
    std::os::unix::fs::symlink(tree.path.join("target"), tree.path.join("links/point")).unwrap();

    // `./target/**` is readable, `./links/**` is not deletable.
    let n = tree.load(b"[filesystem]\nallow read ./target/**\nallow delete ./target/**\n");

    // Deleting through the link is denied, because the link lives in
    // ./links, which has no delete rule.
    assert!(
        matches!(n.delete("./links/point"), Err(NiteraOperationError::Denied)),
        "delete must judge the link's own location, not its target"
    );
}

/// `execute` must authorize the resolved working directory, not the
/// caller's spelling of it.
///
/// A symlinked `cwd` inside an allowed scope resolves to a directory outside
/// it, and the scope check has to see the resolved location or a command
/// would run somewhere the policy never permitted.
#[test]
fn execute_authorizes_the_resolved_working_directory() {
    let tree = Tree::new("guard-exec");
    tree.dir("work");
    tree.dir("outside");

    // The scope covers ./work/**, and only `true` is allowed to run there.
    let n = tree.load(b"[process]\nallow command true\nallow scope ./work/**\n");

    // A symlink inside the scoped directory that points out of it.
    if !symlinks_available() {
        eprintln!("reported as skipped: symlinks are not creatable on this platform");
        return;
    }
    std::os::unix::fs::symlink(tree.path.join("outside"), tree.path.join("work/escape")).unwrap();

    // Running in the scoped directory directly is allowed.
    assert!(
        n.execute("true", Vec::<String>::new(), "./work").is_ok(),
        "the scoped directory itself must still be usable"
    );

    // Running through the symlink must not be, because it resolves outside
    // the scope.
    assert!(
        matches!(
            n.execute("true", Vec::<String>::new(), "./work/escape"),
            Err(NiteraOperationError::Denied)
        ),
        "a symlinked cwd must not escape the allowed scope"
    );
}

/// A dangling symlink must not let `write` plant bytes in a denied
/// directory.
///
/// The final symlink's target does not exist, so `canonicalize` cannot
/// resolve the path. An implementation that walked to the nearest existing
/// ancestor and appended the tail would authorize the *link* while the
/// kernel wrote through it to the *target*, and the deny would never fire.
#[test]
fn dangling_symlink_cannot_plant_bytes_in_a_denied_directory() {
    let tree = Tree::new("guard-dangling");
    tree.dir("denied");
    tree.dir("a");

    if !symlinks_available() {
        eprintln!("reported as skipped: symlinks are not creatable on this platform");
        return;
    }
    // Dangling: `denied/planted` does not exist yet.
    std::os::unix::fs::symlink(tree.path.join("denied/planted"), tree.path.join("a/link")).unwrap();
    assert!(
        !tree.path.join("denied/planted").exists(),
        "the symlink target must not exist for this to be the dangling case"
    );

    let n = tree.load(b"[filesystem]\nallow write ./**\ndeny write ./denied/**\n");

    let result = n.write("./a/link", b"PLANTED");
    assert!(
        matches!(result, Err(NiteraOperationError::Denied)),
        "a write through a dangling symlink into a denied directory must be denied, got {result:?}"
    );
    assert!(
        !tree.path.join("denied/planted").exists(),
        "no bytes may be planted in the denied directory"
    );
}

/// `create` through a dangling symlink must not reach the target directory.
///
/// `create` authorizes the *entry's own location* rather than its target,
/// because creating a new entry never writes through a link. Here the link
/// already exists, so the exclusive create refuses it and reports
/// `AlreadyExists`. Either refusal is fine; what matters is that nothing
/// appears in the denied directory and the call does not succeed.
#[test]
fn dangling_symlink_cannot_create_in_a_denied_directory() {
    let tree = Tree::new("guard-dangling-create");
    tree.dir("denied");
    tree.dir("a");

    if !symlinks_available() {
        eprintln!("reported as skipped: symlinks are not creatable on this platform");
        return;
    }
    std::os::unix::fs::symlink(tree.path.join("denied/fresh"), tree.path.join("a/link")).unwrap();

    let n = tree.load(b"[filesystem]\nallow create ./**\ndeny create ./denied/**\n");

    match n.create("./a/link", b"x") {
        Ok(()) => panic!("create through a dangling symlink must not succeed"),
        Err(NiteraOperationError::Denied) => {}
        // The link already exists, so the exclusive create refuses it.
        Err(NiteraOperationError::AlreadyExists(_)) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
    }
    assert!(
        !tree.path.join("denied/fresh").exists(),
        "no entry may be created in the denied directory"
    );
}

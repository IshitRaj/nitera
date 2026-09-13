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
    let expected_request = format!("Create file {}", target.display());
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
    let expected_request = format!("Create directory {}", target.display());
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

    assert!(matches!(result, Err(NiteraOperationError::AlreadyExists(path)) if path == target));
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

    assert!(matches!(result, Err(NiteraOperationError::AlreadyExists(path)) if path == target));
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

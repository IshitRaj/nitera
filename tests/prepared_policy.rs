use nitera::policy::{matcher::host_matches, parse};
use nitera::{CreateKind, Decision, Nitera, NiteraRequest, Operation, Resource, Target};
use std::path::PathBuf;

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!("nitera-prepared-{}", std::process::id()))
}

#[test]
fn loaded_policy_agrees_with_public_evaluator() {
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let file = root.join("comparison.nitera");
    let mut text = String::from("[filesystem]\n");
    for operation in ["read", "write", "delete", "create"] {
        text.push_str(&format!("allow {operation} ./app/**, ./literal/*.txt, ~/nitera-prepared/**\nask {operation} ./app/*/review/**\ndeny {operation} ./app/**/secret, ./app/blocked/**\n"));
    }
    text.push_str("[process]\nallow scope ./app/**, ~/nitera-prepared/**\nallow command git, sh, cargo\nask command sh\ndeny command cargo\n[network]\nallow host *, *.example.com\nask host *.review.example.com\ndeny host blocked.example.com\n");
    std::fs::write(&file, &text).unwrap();
    let nitera = Nitera::load(&file).unwrap();
    let policy = parse(&text).unwrap();
    let mut paths: Vec<PathBuf> = [
        "",
        ".",
        "./app",
        "./app/",
        "./application/file",
        "./app/x/file",
        "./app/x/review/file",
        "./app/review/file",
        "./app/x/secret",
        "./app/secret",
        "./app/blocked/file",
        "./app/../outside",
        "./app/x/../ok",
        "./literal/*.txt",
        "./literal/x.txt",
        "~/nitera-prepared/file",
        "/",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    paths.push(root.join("app/absolute"));
    paths.push(root.join("app/é/東京"));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        paths.push(
            root.join("app")
                .join(std::ffi::OsString::from_vec(b"invalid-\xff".to_vec())),
        );
    }
    for path in paths {
        let mut requests = Vec::new();
        for operation in [
            Operation::Read,
            Operation::Write,
            Operation::Delete,
            Operation::Create,
            Operation::Execute,
            Operation::Connect,
        ] {
            requests.push(NiteraRequest::filesystem(operation, &path));
        }
        for kind in [CreateKind::File, CreateKind::Directory] {
            requests.push(NiteraRequest::create(&path, kind));
        }
        for command in ["git", "sh", "cargo", "unknown"] {
            requests.push(NiteraRequest::process(command, ["--version"], &path));
        }
        for request in requests {
            assert_eq!(
                nitera.check(&request),
                policy.evaluate(&request, &root),
                "{request:?}"
            );
        }
    }
    for host in [
        "example.com",
        "api.example.com",
        "review.example.com",
        "x.review.example.com",
        "blocked.example.com",
        "é.example.com",
        "example.com.",
    ] {
        let request = NiteraRequest::network(host, 443);
        assert_eq!(nitera.check(&request), policy.evaluate(&request, &root));
    }
    let mismatched = NiteraRequest {
        resource: Resource::Network,
        operation: Operation::Read,
        target: Target::Path(root.join("app/file")),
    };
    assert_eq!(
        nitera.check(&mismatched),
        policy.evaluate(&mismatched, &root)
    );
    std::fs::remove_file(file).unwrap();
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn host_suffix_matching_preserves_original_edge_cases() {
    for pattern in [
        "*",
        "*.",
        "*.example.com",
        "*..example.com",
        "*.é",
        "example.com",
        "",
    ] {
        for host in [
            "",
            ".",
            "example.com",
            ".example.com",
            "x.example.com",
            "notexample.com",
            "x..example.com",
            "x.é",
            "example.com.",
        ] {
            let expected = if pattern == "*" {
                true
            } else if let Some(suffix) = pattern.strip_prefix("*.") {
                host.ends_with(&format!(".{suffix}"))
            } else {
                pattern == host
            };
            assert_eq!(
                host_matches(pattern, host),
                expected,
                "{pattern:?} / {host:?}"
            );
        }
    }
}

#[test]
fn home_changes_preserve_existing_policy_behavior() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "home_changes_child", "--test-threads=1"])
        .env("NITERA_HOME_CHANGE_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn home_changes_child() {
    if std::env::var_os("NITERA_HOME_CHANGE_CHILD").is_none() {
        return;
    }
    let root = test_root();
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let file = root.join("home.nitera");
    let text = "[filesystem]\nallow read ~/allowed/**, ./local/**\n[process]\nallow scope ~/allowed/**\nallow command git\n";
    std::fs::write(&file, text).unwrap();
    let policy = parse(text).unwrap();
    // This test runs alone in its own child process; no concurrent test can
    // read or mutate the process environment while we exercise changes to it.
    for initial in [Some(root.join("home-a")), None] {
        unsafe {
            if let Some(home) = &initial {
                std::env::set_var("HOME", home);
            } else {
                std::env::remove_var("HOME");
            }
        }
        let nitera = Nitera::load(&file).unwrap();
        for home in [
            initial.clone(),
            Some(root.join("home-b")),
            None,
            initial.clone(),
        ] {
            unsafe {
                if let Some(home) = &home {
                    std::env::set_var("HOME", home);
                } else {
                    std::env::remove_var("HOME");
                }
            }
            for path in [
                PathBuf::from("~/allowed/file"),
                root.join("home-a/allowed/file"),
                root.join("home-b/allowed/file"),
                root.join("local/file"),
            ] {
                for request in [
                    NiteraRequest::filesystem(Operation::Read, &path),
                    NiteraRequest::process("git", ["status"], &path),
                ] {
                    assert_eq!(
                        nitera.check(&request),
                        policy.evaluate(&request, &root),
                        "{request:?}, HOME={home:?}"
                    );
                }
            }
        }
    }

    // A failed or stale home-relative deny must never be bypassed by a broad
    // allow. Assert the outcome directly, independently of the public evaluator.
    for filler_count in [0, 128] {
        let mut text = String::from("[filesystem]\ndeny read ~/private/**\nallow read /**\n");
        for i in 0..filler_count {
            text.push_str(&format!("deny read /indexed-other-{i}/**\n"));
        }
        std::fs::write(&file, text).unwrap();
        for initial in [Some(root.join("old-home")), None] {
            unsafe {
                if let Some(home) = &initial {
                    std::env::set_var("HOME", home);
                } else {
                    std::env::remove_var("HOME");
                }
            }
            let nitera = Nitera::load(&file).unwrap();
            let home = root.join("restored-home");
            unsafe {
                std::env::set_var("HOME", &home);
            }
            let private = home.join("private/secret");
            assert_eq!(
                nitera.check(&NiteraRequest::filesystem(Operation::Read, private)),
                Decision::Deny,
            );
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt;
                let path = home
                    .join("private")
                    .join(std::ffi::OsString::from_vec(b"secret-\xff".to_vec()));
                assert_eq!(
                    nitera.check(&NiteraRequest::filesystem(Operation::Read, path)),
                    Decision::Deny,
                );
            }
            unsafe {
                std::env::remove_var("HOME");
            }
            assert_eq!(
                nitera.check(&NiteraRequest::filesystem(
                    Operation::Read,
                    root.join("public")
                )),
                Decision::Deny,
            );
        }
    }
    std::fs::remove_file(file).unwrap();
    std::fs::remove_dir(root).unwrap();
}

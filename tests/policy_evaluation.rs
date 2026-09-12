#[cfg(test)]
mod tests {
    use std::path::Path;

    use nitera::engine::{Decision, NiteraRequest, Operation};
    use nitera::policy::Policy;
    use nitera::policy::model::{
        FilesystemPolicy, FilesystemRules, HostPattern, NetworkPolicy, PathPattern, ProcessPolicy,
    };

    fn test_policy() -> Policy {
        Policy {
            filesystem: FilesystemPolicy {
                allow: FilesystemRules {
                    read: vec![PathPattern("/home/user/project/file.txt".into())],
                    ..Default::default()
                },
                ..Default::default()
            },
            process: ProcessPolicy::default(),
            network: NetworkPolicy::default(),
        }
    }

    #[test]
    fn allowed_read_returns_allow() {
        let policy = test_policy();

        let request = NiteraRequest::filesystem(Operation::Read, "/home/user/project/file.txt");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Allow);
    }

    #[test]
    fn unknown_read_returns_deny() {
        let policy = test_policy();

        let request = NiteraRequest::filesystem(Operation::Read, "/etc/passwd");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn wildcard_pattern_allows_nested_path() {
        let home = std::env::var("HOME").unwrap();

        let policy = Policy {
            filesystem: FilesystemPolicy {
                allow: FilesystemRules {
                    read: vec![PathPattern(format!("{home}/projects/**"))],
                    ..Default::default()
                },
                ..Default::default()
            },
            process: ProcessPolicy::default(),
            network: NetworkPolicy::default(),
        };

        let request = NiteraRequest::filesystem(
            Operation::Read,
            format!("{home}/projects/myapp/src/main.rs"),
        );

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Allow);
    }

    #[test]
    fn allow_write_returns_allow() {
        let policy = Policy {
            filesystem: FilesystemPolicy {
                allow: FilesystemRules {
                    write: vec![PathPattern("/tmp/**".into())],
                    ..Default::default()
                },
                ..Default::default()
            },
            process: ProcessPolicy::default(),
            network: NetworkPolicy::default(),
        };

        let request = NiteraRequest::filesystem(Operation::Write, "/tmp/test.txt");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Allow);
    }

    #[test]
    fn deny_overrides_allow_for_read() {
        let policy = Policy {
            filesystem: FilesystemPolicy {
                allow: FilesystemRules {
                    read: vec![PathPattern("/tmp/**".into())],
                    ..Default::default()
                },
                deny: FilesystemRules {
                    read: vec![PathPattern("/tmp/secret/**".into())],
                    ..Default::default()
                },
                ..Default::default()
            },
            process: ProcessPolicy::default(),
            network: NetworkPolicy::default(),
        };

        let request = NiteraRequest::filesystem(Operation::Read, "/tmp/secret/password.txt");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn ask_overrides_allow_for_read() {
        let policy = Policy {
            filesystem: FilesystemPolicy {
                allow: FilesystemRules {
                    read: vec![PathPattern("/tmp/**".into())],
                    ..Default::default()
                },
                ask: FilesystemRules {
                    read: vec![PathPattern("/tmp/important/**".into())],
                    ..Default::default()
                },
                ..Default::default()
            },
            process: ProcessPolicy::default(),
            network: NetworkPolicy::default(),
        };

        let request = NiteraRequest::filesystem(Operation::Read, "/tmp/important/file.txt");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Ask);
    }

    #[test]
    fn allow_delete_returns_allow() {
        let policy = Policy {
            filesystem: FilesystemPolicy {
                allow: FilesystemRules {
                    delete: vec![PathPattern("/tmp/**".into())],
                    ..Default::default()
                },
                ..Default::default()
            },
            process: ProcessPolicy::default(),
            network: NetworkPolicy::default(),
        };

        let request = NiteraRequest::filesystem(Operation::Delete, "/tmp/test.txt");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Allow);
    }

    #[test]
    fn unmatched_operation_fails_closed_to_deny() {
        // No rules configured anywhere for this policy at all.
        let policy = Policy {
            filesystem: FilesystemPolicy::default(),
            process: ProcessPolicy::default(),
            network: NetworkPolicy::default(),
        };

        let request = NiteraRequest::filesystem(Operation::Write, "/anything/at/all.txt");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn allowed_process_returns_allow() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["cargo".into()],
                scope: vec![PathPattern("/projects/**".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::process("cargo", ["test"], "/projects/myapp");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Allow);
    }

    #[test]
    fn unknown_process_returns_deny() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["cargo".into()],
                scope: vec![PathPattern("/projects/**".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::process("python", ["script.py"], "/projects/myapp");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn denied_process_returns_deny() {
        let policy = Policy {
            process: ProcessPolicy {
                deny: vec!["bash".into()],
                scope: vec![PathPattern("/projects/**".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::process("bash", [""], "/projects/myapp");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn ask_process_returns_ask() {
        let policy = Policy {
            process: ProcessPolicy {
                ask: vec!["rm".into()],
                scope: vec![PathPattern("/projects/**".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::process("rm", ["file.txt"], "/projects/myapp");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Ask);
    }

    #[test]
    fn process_outside_scope_returns_deny() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["cargo".into()],
                scope: vec![PathPattern("/projects/**".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::process("cargo", ["test"], "/tmp");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn denied_process_overrides_allowed_process() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["cargo".into()],
                deny: vec!["cargo".into()],
                scope: vec![PathPattern("/projects/**".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::process("cargo", ["test"], "/projects/myapp");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn asked_process_overrides_allowed_process() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["cargo".into()],
                ask: vec!["cargo".into()],
                scope: vec![PathPattern("/projects/**".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::process("cargo", ["test"], "/projects/myapp");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Ask);
    }

    #[test]
    fn empty_scope_denies_process() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["cargo".into()],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::process("cargo", ["test"], "/projects/myapp");

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn allowed_host_returns_allow() {
        let policy = Policy {
            network: NetworkPolicy {
                allow: vec![HostPattern("api.github.com".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::network("api.github.com", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Allow);
    }

    #[test]
    fn unknown_host_returns_deny() {
        let policy = Policy {
            network: NetworkPolicy {
                allow: vec![HostPattern("api.github.com".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::network("example.com", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn wildcard_host_returns_allow() {
        let policy = Policy {
            network: NetworkPolicy {
                allow: vec![HostPattern("*.crates.io".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::network("api.crates.io", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Allow);
    }

    #[test]
    fn wildcard_host_does_not_match_parent_domain() {
        let policy = Policy {
            network: NetworkPolicy {
                allow: vec![HostPattern("*.crates.io".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::network("crates.io", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn denied_host_returns_deny() {
        let policy = Policy {
            network: NetworkPolicy {
                deny: vec![HostPattern("evil.com".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::network("evil.com", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn deny_overrides_allow_for_host() {
        let policy = Policy {
            network: NetworkPolicy {
                allow: vec![HostPattern("*.example.com".into())],
                deny: vec![HostPattern("api.example.com".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::network("api.example.com", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn ask_overrides_allow_for_host() {
        let policy = Policy {
            network: NetworkPolicy {
                allow: vec![HostPattern("*.example.com".into())],
                ask: vec![HostPattern("api.example.com".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::network("api.example.com", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Ask);
    }

    #[test]
    fn global_wildcard_deny_returns_deny() {
        let policy = Policy {
            network: NetworkPolicy {
                deny: vec![HostPattern("*".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::network("example.com", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn allowed_host_overrides_global_deny() {
        let policy = Policy {
            network: NetworkPolicy {
                allow: vec![HostPattern("api.github.com".into())],
                deny: vec![HostPattern("*".into())],
                ..Default::default()
            },
            ..Default::default()
        };

        let request = NiteraRequest::network("api.github.com", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }

    #[test]
    fn empty_network_policy_fails_closed_to_deny() {
        let policy = Policy {
            network: NetworkPolicy::default(),
            ..Default::default()
        };

        let request = NiteraRequest::network("example.com", 443);

        assert_eq!(policy.evaluate(&request, Path::new("/")), Decision::Deny);
    }
}

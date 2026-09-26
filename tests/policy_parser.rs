use nitera::policy::model::{HostPattern, PathPattern, Policy};
use nitera::policy::parser::parse;

#[test]
fn parses_empty_policy() {
    let policy = parse("").unwrap();
    assert_eq!(policy, Policy::default());
}

#[test]
fn parses_sections() {
    let input = r#"
        [filesystem]
        
        [process]

        [network]
    "#;

    let policy = parse(input).unwrap();

    assert_eq!(policy, Policy::default());
}

#[test]
fn ignores_blank_lines_and_comments() {
    let input = r#"
        # Nitera policy

        [filesystem]

        # Process rules will come later

        [process]

        [network]
    "#;

    assert_eq!(parse(input).unwrap(), Policy::default());
}

#[test]
fn rejects_unknown_section() {
    let error = parse("[unknown]").unwrap_err();

    assert_eq!(error.line, 1);
}

#[test]
fn rejects_rule_before_section() {
    let error = parse("allow read /tmp/**").unwrap_err();

    assert_eq!(error.line, 1);
}

#[test]
fn parses_filesystem_read_rule() {
    let policy = parse(
        r#"
        [filesystem]
        allow read ~/projects/**
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.filesystem.allow.read,
        vec![PathPattern("~/projects/**".into())]
    );
}

#[test]
fn parses_multiple_filesystem_paths() {
    let policy = parse(
        r#"
        [filesystem]
        allow read ~/projects/**, /tmp/**, /var/tmp/**
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.filesystem.allow.read,
        vec![
            PathPattern("~/projects/**".into()),
            PathPattern("/tmp/**".into()),
            PathPattern("/var/tmp/**".into()),
        ]
    );
}

#[test]
fn parses_all_filesystem_operations() {
    let policy = parse(
        r#"
        [filesystem]
        allow read ~/projects/**
        ask write /tmp/**
        deny delete /etc/**
        allow create ./playground/**
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.filesystem.allow.read,
        vec![PathPattern("~/projects/**".into())]
    );

    assert_eq!(
        policy.filesystem.ask.write,
        vec![PathPattern("/tmp/**".into())]
    );

    assert_eq!(
        policy.filesystem.deny.delete,
        vec![PathPattern("/etc/**".into())]
    );

    assert_eq!(
        policy.filesystem.allow.create,
        vec![PathPattern("./playground/**".into())]
    );
}

#[test]
fn parses_ask_and_deny_create_rules() {
    let policy = parse(
        r#"
        [filesystem]
        ask create ./review/**
        deny create ./protected/**
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.filesystem.ask.create,
        vec![PathPattern("./review/**".into())]
    );
    assert_eq!(
        policy.filesystem.deny.create,
        vec![PathPattern("./protected/**".into())]
    );
}

#[test]
fn rejects_unknown_filesystem_action() {
    let error = parse(
        r#"
        [filesystem]
        block read /tmp/**
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn rejects_unknown_filesystem_operation() {
    let error = parse(
        r#"
        [filesystem]
        allow execute /tmp/**
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn rejects_missing_filesystem_path() {
    let error = parse(
        r#"
        [filesystem]
        allow read
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn parses_process_allow_commands() {
    let policy = parse(
        r#"
        [process]
        allow command git, cargo, node, npm
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.process.allow,
        vec![
            "git".to_string(),
            "cargo".to_string(),
            "node".to_string(),
            "npm".to_string(),
        ]
    );
}

#[test]
fn parses_process_ask_commands() {
    let policy = parse(
        r#"
        [process]
        ask command rm, sudo, chmod
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.process.ask,
        vec!["rm".to_string(), "sudo".to_string(), "chmod".to_string(),]
    );
}

#[test]
fn parses_process_deny_commands() {
    let policy = parse(
        r#"
        [process]
        deny command dd, mkfs, shutdown, bash, sh
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.process.deny,
        vec![
            "dd".to_string(),
            "mkfs".to_string(),
            "shutdown".to_string(),
            "bash".to_string(),
            "sh".to_string(),
        ]
    );
}

#[test]
fn parses_process_scope() {
    let policy = parse(
        r#"
        [process]
        allow scope ~/projects/**
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.process.scope,
        vec![PathPattern("~/projects/**".into())]
    );
}

#[test]
fn parses_process_scope_comma_separated() {
    let policy = parse(
        r#"
        [process]
        allow scope ~/projects/apps/web/**, ~/projects/apps/cli/**
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.process.scope,
        vec![
            PathPattern("~/projects/apps/web/**".into()),
            PathPattern("~/projects/apps/cli/**".into()),
        ]
    );
}

#[test]
fn parses_complete_process_policy() {
    let policy = parse(
        r#"
        [process]
        allow command git, cargo, node, npm
        ask command rm, sudo, chmod
        deny command dd, mkfs, shutdown, bash, sh
        allow scope ~/projects/**
        "#,
    )
    .unwrap();

    assert_eq!(policy.process.allow.len(), 4);
    assert_eq!(policy.process.ask.len(), 3);
    assert_eq!(policy.process.deny.len(), 5);

    assert_eq!(
        policy.process.scope,
        vec![PathPattern("~/projects/**".into())]
    );
}

#[test]
fn rejects_unknown_process_rule() {
    let error = parse(
        r#"
        [process]
        allow program cargo
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn rejects_unknown_process_action() {
    let error = parse(
        r#"
        [process]
        block command cargo
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn rejects_missing_process_command() {
    let error = parse(
        r#"
        [process]
        allow command
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn rejects_missing_process_scope() {
    let error = parse(
        r#"
        [process]
        scope
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn parses_network_allow_hosts() {
    let policy = parse(
        r#"
        [network]
        allow host api.github.com, *.crates.io, registry.npmjs.org
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.network.allow,
        vec![
            HostPattern("api.github.com".into()),
            HostPattern("*.crates.io".into()),
            HostPattern("registry.npmjs.org".into()),
        ]
    );
}

#[test]
fn parses_network_ask_hosts() {
    let policy = parse(
        r#"
        [network]
        ask host example.com, api.example.com
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.network.ask,
        vec![
            HostPattern("example.com".into()),
            HostPattern("api.example.com".into()),
        ]
    );
}

#[test]
fn parses_network_deny_hosts() {
    let policy = parse(
        r#"
        [network]
        deny host *
        "#,
    )
    .unwrap();

    assert_eq!(policy.network.deny, vec![HostPattern("*".into())]);
}

#[test]
fn parses_complete_network_policy() {
    let policy = parse(
        r#"
        [network]
        allow host api.github.com, *.crates.io
        ask host example.com
        deny host *
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.network.allow,
        vec![
            HostPattern("api.github.com".into()),
            HostPattern("*.crates.io".into()),
        ]
    );

    assert_eq!(policy.network.ask, vec![HostPattern("example.com".into())]);
    assert_eq!(policy.network.deny, vec![HostPattern("*".into())]);
}

#[test]
fn rejects_unknown_network_rule() {
    let error = parse(
        r#"
        [network]
        allow address example.com
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn rejects_unknown_network_action() {
    let error = parse(
        r#"
        [network]
        block host example.com
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn rejects_missing_network_host() {
    let error = parse(
        r#"
        [network]
        allow host
        "#,
    )
    .unwrap_err();

    assert_eq!(error.line, 3);
}

#[test]
fn parses_network_hosts_with_whitespace() {
    let policy = parse(
        r#"
        [network]
        allow host api.github.com,   *.crates.io,registry.npmjs.org
        "#,
    )
    .unwrap();

    assert_eq!(
        policy.network.allow,
        vec![
            HostPattern("api.github.com".into()),
            HostPattern("*.crates.io".into()),
            HostPattern("registry.npmjs.org".into()),
        ]
    );
}

#[test]
fn tolerates_runs_of_whitespace_between_action_and_kind() {
    // A double space used to produce an empty `kind` field, which then
    // failed as "unknown filesystem operation: " with a blank name.
    let policy = parse("[filesystem]\nallow  read ./a\n").unwrap();

    assert_eq!(
        policy.filesystem.allow.read,
        vec![PathPattern("./a".into())]
    );
}

#[test]
fn tolerates_mixed_tabs_and_spaces_between_fields() {
    let policy = parse("[filesystem]\nallow\t \tread ./a\n").unwrap();

    assert_eq!(
        policy.filesystem.allow.read,
        vec![PathPattern("./a".into())]
    );
}

#[test]
fn values_field_still_keeps_spaces_around_commas() {
    // Splitting the whole line on whitespace would drop every value after
    // the first, so the third field has to stay "rest of line".
    let policy = parse("[filesystem]\nallow read ./a, ./b ,  ./c\n").unwrap();

    assert_eq!(
        policy.filesystem.allow.read,
        vec![
            PathPattern("./a".into()),
            PathPattern("./b".into()),
            PathPattern("./c".into()),
        ]
    );
}

#[test]
fn still_reports_missing_rule_when_there_is_no_second_field() {
    let error = parse("[filesystem]\nallow\n").unwrap_err();

    assert_eq!(error.line, 2);
    assert_eq!(error.message, "missing rule");
}

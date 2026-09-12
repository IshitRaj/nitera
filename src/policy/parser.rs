use super::model::{HostPattern, PathPattern, Policy};

struct Rule<'a> {
    action: &'a str,
    kind: &'a str,
    values: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl ParseError {
    fn new(line: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Filesystem,
    Process,
    Network,
}

fn parse_rule<'a>(line: &'a str, line_number: usize) -> Result<Rule<'a>, ParseError> {
    let mut parts = line.splitn(3, char::is_whitespace);

    let action = parts
        .next()
        .ok_or_else(|| ParseError::new(line_number, "missing action"))?;

    let kind = parts
        .next()
        .ok_or_else(|| ParseError::new(line_number, "missing rule"))?;

    let values = parts.next().unwrap_or("").trim();

    Ok(Rule {
        action,
        kind,
        values,
    })
}

fn parse_values(values: &str, line_number: usize, error: &str) -> Result<Vec<String>, ParseError> {
    let values = values
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    if values.is_empty() {
        return Err(ParseError::new(line_number, error));
    }

    Ok(values)
}

fn parse_filesystem_rule(
    line: &str,
    policy: &mut Policy,
    line_number: usize,
) -> Result<(), ParseError> {
    let rule = parse_rule(line, line_number)?;

    let rules = match rule.action {
        "allow" => &mut policy.filesystem.allow,
        "ask" => &mut policy.filesystem.ask,
        "deny" => &mut policy.filesystem.deny,
        _ => {
            return Err(ParseError::new(
                line_number,
                format!("unknown action: {}", rule.action),
            ));
        }
    };

    let values = parse_values(rule.values, line_number, "missing filesystem path")?;
    let patterns = values.into_iter().map(PathPattern).collect::<Vec<_>>();

    match rule.kind {
        "read" => rules.read.extend(patterns),
        "write" => rules.write.extend(patterns),
        "delete" => rules.delete.extend(patterns),
        "create" => rules.create.extend(patterns),
        _ => {
            return Err(ParseError::new(
                line_number,
                format!("unknown filesystem operation: {}", rule.kind),
            ));
        }
    }

    Ok(())
}

fn parse_process_rule(
    line: &str,
    policy: &mut Policy,
    line_number: usize,
) -> Result<(), ParseError> {
    let rule = parse_rule(line, line_number)?;

    match rule.kind {
        "scope" => {
            if rule.action != "allow" {
                return Err(ParseError::new(line_number, "scope can only use allow"));
            }

            let scopes = parse_values(rule.values, line_number, "missing process scope")?;

            policy
                .process
                .scope
                .extend(scopes.into_iter().map(PathPattern));
        }

        "command" => {
            let commands = parse_values(rule.values, line_number, "missing process command")?;

            let rules = match rule.action {
                "allow" => &mut policy.process.allow,
                "ask" => &mut policy.process.ask,
                "deny" => &mut policy.process.deny,
                _ => {
                    return Err(ParseError::new(
                        line_number,
                        format!("unknown process action: {}", rule.action),
                    ));
                }
            };

            rules.extend(commands);
        }

        _ => {
            return Err(ParseError::new(
                line_number,
                format!("unknown process rule: {}", rule.kind),
            ));
        }
    }

    Ok(())
}

fn parse_network_rule(
    line: &str,
    policy: &mut Policy,
    line_number: usize,
) -> Result<(), ParseError> {
    let rule = parse_rule(line, line_number)?;

    match rule.kind {
        "host" => {
            let hosts = parse_values(rule.values, line_number, "missing network host")?;

            let rules = match rule.action {
                "allow" => &mut policy.network.allow,
                "ask" => &mut policy.network.ask,
                "deny" => &mut policy.network.deny,
                _ => {
                    return Err(ParseError::new(
                        line_number,
                        format!("unknown network action: {}", rule.action),
                    ));
                }
            };

            rules.extend(hosts.into_iter().map(HostPattern));
        }

        _ => {
            return Err(ParseError::new(
                line_number,
                format!("unknown network rule: {}", rule.action),
            ));
        }
    }

    Ok(())
}

pub fn parse(input: &str) -> Result<Policy, ParseError> {
    let mut policy = Policy::default();
    let mut section: Option<Section> = None;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;

        // Remove comments.
        let line = raw_line.split('#').next().unwrap_or("").trim();

        // Ignore blank lines.
        if line.is_empty() {
            continue;
        }

        // Parse section headers.
        if line.starts_with('[') && line.ends_with(']') {
            section = Some(match line {
                "[filesystem]" => Section::Filesystem,
                "[process]" => Section::Process,
                "[network]" => Section::Network,
                _ => {
                    return Err(ParseError::new(
                        line_number,
                        format!("unknown section: {line}"),
                    ));
                }
            });

            continue;
        }

        // Rules aren't implemented yet.
        match section {
            Some(Section::Filesystem) => {
                parse_filesystem_rule(line, &mut policy, line_number)?;
            }
            Some(Section::Process) => {
                parse_process_rule(line, &mut policy, line_number)?;
            }
            Some(Section::Network) => {
                parse_network_rule(line, &mut policy, line_number)?;
            }
            None => {
                return Err(ParseError::new(line_number, "rule found before a section"));
            }
        }
    }

    Ok(policy)
}

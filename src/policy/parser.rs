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

/// Split off the next whitespace-delimited field, returning it with the
/// remainder. Leading whitespace is skipped, so a run of separators
/// between `action` and `kind` does not yield an empty field.
fn take_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    Some(match input.find(char::is_whitespace) {
        Some(end) => (&input[..end], &input[end..]),
        None => (input, ""),
    })
}

fn parse_rule<'a>(line: &'a str, line_number: usize) -> Result<Rule<'a>, ParseError> {
    let line = line.trim();

    let Some((action, after_action)) = take_field(line) else {
        return Err(ParseError::new(line_number, "missing action"));
    };

    let Some((kind, values)) = take_field(after_action) else {
        return Err(ParseError::new(line_number, "missing rule"));
    };

    Ok(Rule {
        action,
        kind,
        // The values field is the rest of the line rather than a third
        // whitespace split, so a list can contain spaces around commas.
        values: values.trim(),
    })
}

fn parse_values(values: &str, line_number: usize, error: &str) -> Result<Vec<String>, ParseError> {
    let mut parsed = Vec::new();
    let mut value = String::new();
    let mut chars = values.chars().peekable();
    let mut quoted = false;
    let mut was_quoted = false;
    let mut token_started = false;

    while let Some(ch) = chars.next() {
        if quoted {
            match ch {
                '\\' => match chars.next() {
                    Some(escaped @ ('\\' | '"')) => value.push(escaped),
                    Some(other) => {
                        value.push('\\');
                        value.push(other);
                    }
                    None => {
                        return Err(ParseError::new(
                            line_number,
                            "trailing escape in quoted value",
                        ));
                    }
                },
                '"' => quoted = false,
                _ => value.push(ch),
            }
            continue;
        }

        match ch {
            '"' if !token_started && value.trim().is_empty() => {
                value.clear();
                quoted = true;
                was_quoted = true;
                token_started = true;
            }
            ',' => {
                let item = if was_quoted {
                    value.clone()
                } else {
                    value.trim().to_owned()
                };
                if !item.is_empty() {
                    parsed.push(item);
                }
                value.clear();
                token_started = false;
                was_quoted = false;
            }
            _ => {
                value.push(ch);
                if !ch.is_whitespace() {
                    token_started = true;
                }
            }
        }
    }

    if quoted {
        return Err(ParseError::new(line_number, "unclosed quoted value"));
    }
    let item = if was_quoted {
        value.clone()
    } else {
        value.trim().to_owned()
    };
    if !item.is_empty() {
        parsed.push(item);
    }
    let values = parsed;

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

        // Strip comments only outside a quoted value. Bare values retain the
        // legacy interpretation, including any literal quote characters.
        let mut quoted = false;
        let mut escaped = false;
        let mut quote_can_start = true;
        let mut end = raw_line.len();
        for (offset, ch) in raw_line.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if quoted && ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '"' && (quoted || quote_can_start) {
                quoted = !quoted;
                quote_can_start = false;
                continue;
            }
            if ch == '#' && !quoted {
                end = offset;
                break;
            }
            if !quoted {
                if ch == ',' {
                    quote_can_start = true;
                } else if ch.is_whitespace() {
                    quote_can_start = true;
                } else {
                    quote_can_start = false;
                }
            }
        }
        let line = raw_line[..end].trim();

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

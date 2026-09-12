use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Filesystem,
    Process,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    Delete,
    Execute,
    Connect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Path(PathBuf),

    Process {
        command: String,
        args: Vec<String>,
        cwd: PathBuf,
    },

    Network {
        host: String,
        port: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NiteraRequest {
    pub resource: Resource,
    pub operation: Operation,
    pub target: Target,
}

impl std::fmt::Display for NiteraRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.operation, &self.target) {
            (Operation::Read, Target::Path(path)) => write!(f, "read {}", path.display()),
            (Operation::Write, Target::Path(path)) => write!(f, "write {}", path.display()),
            (Operation::Delete, Target::Path(path)) => write!(f, "delete {}", path.display()),
            (Operation::Execute, Target::Process { command, args, cwd }) => {
                if args.is_empty() {
                    write!(f, "run `{command}` in {}", cwd.display())
                } else {
                    write!(f, "run `{command} {}` in {}", args.join(" "), cwd.display())
                }
            }
            (Operation::Connect, Target::Network { host, port }) => {
                write!(f, "connect to {host}:{port}")
            }
            _ => write!(f, "{:?} on {:?}", self.operation, self.target),
        }
    }
}

impl NiteraRequest {
    pub fn filesystem(operation: Operation, path: impl Into<PathBuf>) -> Self {
        Self {
            resource: Resource::Filesystem,
            operation,
            target: Target::Path(path.into()),
        }
    }

    pub fn process<I, S>(command: impl Into<String>, args: I, cwd: impl Into<PathBuf>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            resource: Resource::Process,
            operation: Operation::Execute,
            target: Target::Process {
                command: command.into(),
                args: args.into_iter().map(Into::into).collect(),
                cwd: cwd.into(),
            },
        }
    }

    pub fn network(host: impl Into<String>, port: u16) -> Self {
        Self {
            resource: Resource::Network,
            operation: Operation::Connect,
            target: Target::Network {
                host: host.into(),
                port,
            },
        }
    }
}

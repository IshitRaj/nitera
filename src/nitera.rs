use crate::approval::{ApprovalDecision, ApprovalHandler};
use crate::engine::{Decision, NiteraRequest, Operation};
use crate::policy::path::resolve_runtime_path;
use crate::policy::{ParseError, Policy, parse};
use std::sync::Arc;

/// Errors produced while performing a policy-controlled operation.
#[derive(Debug)]
pub enum NiteraOperationError {
    Denied,
    Ask(NiteraRequest),
    Io(std::io::Error),
}

pub struct Nitera {
    policy: Policy,
    root: std::path::PathBuf,
    approval_handler: Option<Arc<dyn ApprovalHandler>>,
}

impl std::fmt::Display for NiteraOperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NiteraOperationError::Denied => write!(f, "request denied by policy"),
            NiteraOperationError::Ask(request) => write!(
                f,
                "policy marks `{request}` as ask, but no approval handler is configured. \
                 Call `.with_approval_handler(...)` on this Nitera, or handle `NiteraOperationError::Ask` yourself."
            ),
            NiteraOperationError::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for NiteraOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NiteraOperationError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl Nitera {
    /// Loads a Nitera policy from a `.nitera` file.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, NiteraError> {
        let path = path.as_ref();

        if path.extension().and_then(|ext| ext.to_str()) != Some("nitera") {
            return Err(NiteraError::InvalidPolicyFile);
        }

        let contents = std::fs::read_to_string(path).map_err(NiteraError::Io)?;
        let policy = parse(&contents).map_err(NiteraError::Parse)?;

        let root = path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .canonicalize()
            .map_err(NiteraError::Io)?;

        Ok(Self {
            policy,
            root,
            approval_handler: None,
        })
    }

    /// Registers the application callback used to resolve `ask` rules.
    pub fn with_approval_handler(mut self, handler: impl ApprovalHandler + 'static) -> Self {
        self.approval_handler = Some(Arc::new(handler));
        self
    }

    /// Evaluates a request against the loaded policy.
    pub fn check(&self, request: &NiteraRequest) -> Decision {
        self.policy.evaluate(request, &self.root)
    }

    /// Authorizes a request using the policy and, when required, the approval handler.
    ///
    /// `Allow` permits the operation immediately. `Deny` rejects it immediately.
    /// For `Ask`, the configured approval handler is consulted. If no handler is
    /// configured, the request is returned as `NiteraOperationError::Ask`.
    fn authorize(&self, request: &NiteraRequest) -> Result<(), NiteraOperationError> {
        match self.check(request) {
            Decision::Allow => Ok(()),
            Decision::Deny => Err(NiteraOperationError::Denied),
            Decision::Ask => match &self.approval_handler {
                Some(handler) => match handler.approve(request) {
                    ApprovalDecision::Approved => Ok(()),
                    ApprovalDecision::Denied => Err(NiteraOperationError::Denied),
                },
                None => Err(NiteraOperationError::Ask(request.clone())),
            },
        }
    }

    /// Reads a file after policy authorization.
    pub fn read(&self, path: impl AsRef<std::path::Path>) -> Result<Vec<u8>, NiteraOperationError> {
        let request_path =
            resolve_runtime_path(path.as_ref(), &self.root).map_err(NiteraOperationError::Io)?;
        let request = NiteraRequest::filesystem(Operation::Read, request_path.clone());
        self.authorize(&request)?;
        std::fs::read(&request_path).map_err(NiteraOperationError::Io)
    }

    /// Writes a file after policy authorization.
    pub fn write(
        &self,
        path: impl AsRef<std::path::Path>,
        content: impl AsRef<[u8]>,
    ) -> Result<(), NiteraOperationError> {
        let request_path =
            resolve_runtime_path(path.as_ref(), &self.root).map_err(NiteraOperationError::Io)?;
        let request = NiteraRequest::filesystem(Operation::Write, request_path.clone());
        self.authorize(&request)?;
        std::fs::write(&request_path, content).map_err(NiteraOperationError::Io)
    }

    /// Deletes a file after policy authorization.
    pub fn delete(&self, path: impl AsRef<std::path::Path>) -> Result<(), NiteraOperationError> {
        let request_path =
            resolve_runtime_path(path.as_ref(), &self.root).map_err(NiteraOperationError::Io)?;
        let request = NiteraRequest::filesystem(Operation::Delete, request_path.clone());
        self.authorize(&request)?;
        std::fs::remove_file(&request_path).map_err(NiteraOperationError::Io)
    }

    /// Executes a process after policy authorization.
    pub fn execute<I, S>(
        &self,
        command: impl Into<String>,
        args: I,
        cwd: impl AsRef<std::path::Path>,
    ) -> Result<std::process::Output, NiteraOperationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let command = command.into();
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        let request_cwd =
            resolve_runtime_path(cwd.as_ref(), &self.root).map_err(NiteraOperationError::Io)?;
        let request = NiteraRequest::process(&command, args.clone(), request_cwd.clone());
        self.authorize(&request)?;
        std::process::Command::new(&command)
            .args(&args)
            .current_dir(&request_cwd)
            .output()
            .map_err(NiteraOperationError::Io)
    }

    /// Opens a TCP connection after policy authorization.
    pub fn connect(
        &self,
        host: impl Into<String>,
        port: u16,
    ) -> Result<std::net::TcpStream, NiteraOperationError> {
        let host = host.into();
        let request = NiteraRequest::network(&host, port);
        self.authorize(&request)?;
        std::net::TcpStream::connect((host.as_str(), port)).map_err(NiteraOperationError::Io)
    }
}

/// Errors produced while loading a Nitera policy.
#[derive(Debug)]
pub enum NiteraError {
    InvalidPolicyFile,
    Io(std::io::Error),
    Parse(ParseError),
}

impl std::fmt::Display for NiteraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NiteraError::InvalidPolicyFile => {
                write!(f, "policy file must have a `.nitera` extension")
            }
            NiteraError::Io(err) => write!(f, "failed to read policy file: {err}"),
            NiteraError::Parse(err) => write!(f, "invalid policy file: {err}"),
        }
    }
}

impl std::error::Error for NiteraError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NiteraError::Io(err) => Some(err),
            NiteraError::Parse(err) => Some(err),
            NiteraError::InvalidPolicyFile => None,
        }
    }
}

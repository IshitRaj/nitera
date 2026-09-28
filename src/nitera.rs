use crate::approval::{ApprovalDecision, ApprovalHandler};
use crate::engine::{CreateKind, Decision, NiteraRequest, Operation};
use crate::policy::path::{resolve_aliases, resolve_entry_location, resolve_runtime_path};
use crate::policy::prepared::{MatchMode, PreparedPolicy};
use crate::policy::{ParseError, parse};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Errors produced while performing a policy-controlled operation.
#[derive(Debug)]
pub enum NiteraOperationError {
    Denied,
    Ask(NiteraRequest),
    Io(std::io::Error),
    AlreadyExists(PathBuf),
}

pub struct Nitera {
    policy: PreparedPolicy,
    root: std::path::PathBuf,
    approval_handler: Option<Arc<dyn ApprovalHandler>>,
}

/// Prints the policy root and whether an approval handler is registered,
/// without reaching into the prepared policy or the handler itself.
impl std::fmt::Debug for Nitera {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nitera")
            .field("root", &self.root)
            .field(
                "approval_handler",
                if self.approval_handler.is_some() {
                    &"registered"
                } else {
                    &"none"
                },
            )
            .finish()
    }
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
            NiteraOperationError::AlreadyExists(path) => {
                write!(f, "target already exists: {}", path.display())
            }
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
    ///
    /// The path must either carry a `nitera` extension (`policy.nitera`)
    /// or be named exactly `.nitera`. The latter is a dotfile, so
    /// `Path::extension` reports no extension for it.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, NiteraError> {
        let path = path.as_ref();

        if !has_nitera_extension(path) {
            return Err(NiteraError::InvalidPolicyFile);
        }

        let contents = std::fs::read_to_string(path).map_err(NiteraError::Io)?;
        let policy = parse(&contents).map_err(NiteraError::Parse)?;

        let root = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."))
            .canonicalize()
            .map_err(NiteraError::Io)?;

        Ok(Self {
            policy: PreparedPolicy::new(policy, &root),
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
    ///
    /// This is the advisory path. It matches the request's path lexically,
    /// without touching the filesystem, so it does not resolve symlinks or
    /// filesystem aliases and cannot see through them. A caller that needs
    /// the same decision a guarded operation would make should use the
    /// guarded method, which authorizes the resolved location.
    pub fn check(&self, request: &NiteraRequest) -> Decision {
        self.policy
            .evaluate(request, &self.root, MatchMode::Lexical)
    }

    /// Resolves a request path, authorizes the resolved location, and
    /// returns the path to hand to the operating system.
    ///
    /// The returned path is the one that was authorized, so the check and
    /// the syscall cannot disagree about which resource is touched. This
    /// closes the alias bypasses in SECURITY-AUDIT items 1 and 18: a
    /// symlink, or a prefix such as macOS `/tmp`, inside an allowed
    /// directory can no longer reach a denied file, because the deny is
    /// evaluated against the resolved location and not the requested name.
    ///
    /// `follow_final_component` is false for operations that act on a
    /// directory entry rather than on whatever it resolves to. Unlinking a
    /// symlink removes the link and not its target, so `delete` resolves
    /// only the parent and keeps the final component literal.
    fn authorize_resolved(
        &self,
        operation: Operation,
        path: &Path,
        follow_final_component: bool,
        build_request: impl FnOnce(PathBuf) -> NiteraRequest,
    ) -> Result<PathBuf, NiteraOperationError> {
        // A policy that never mentions this operation denies it, and saying
        // so costs nothing. Resolving first would spend a `canonicalize` to
        // reach the same answer.
        if self.policy.filesystem_authorizes_nothing(&operation) {
            return Err(NiteraOperationError::Denied);
        }

        let lexical = resolve_runtime_path(path, &self.root).map_err(NiteraOperationError::Io)?;

        let resolved = if follow_final_component {
            resolve_aliases(&lexical).map_err(NiteraOperationError::Io)?
        } else {
            resolve_entry_location(&lexical).map_err(NiteraOperationError::Io)?
        };

        // Authorize the resolved form, which is the form the syscall uses.
        self.authorize_in_mode(&build_request(resolved.clone()), MatchMode::Resolved)?;

        Ok(resolved)
    }

    /// Authorizes a request using the policy and, when required, the approval handler.
    ///
    /// `Allow` permits the operation immediately. `Deny` rejects it immediately.
    /// For `Ask`, the configured approval handler is consulted. If no handler is
    /// configured, the request is returned as `NiteraOperationError::Ask`.
    fn authorize(&self, request: &NiteraRequest) -> Result<(), NiteraOperationError> {
        self.authorize_in_mode(request, MatchMode::Lexical)
    }

    /// Authorizes a request against the loaded policy in the given form.
    ///
    /// The `ask` handling is identical in both forms. The handler receives
    /// the same request that was evaluated and returns only a decision, so
    /// approving a resolved request still cannot substitute a different
    /// path, host, or command.
    fn authorize_in_mode(
        &self,
        request: &NiteraRequest,
        mode: MatchMode,
    ) -> Result<(), NiteraOperationError> {
        match self.policy.evaluate(request, &self.root, mode) {
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
    ///
    /// The path is resolved to the location the operating system will use
    /// and that resolved location is what gets authorized and read, so a
    /// symlinked or aliased path cannot reach a denied file.
    pub fn read(&self, path: impl AsRef<std::path::Path>) -> Result<Vec<u8>, NiteraOperationError> {
        let resolved =
            self.authorize_resolved(Operation::Read, path.as_ref(), true, |resolved| {
                NiteraRequest::filesystem(Operation::Read, resolved)
            })?;
        std::fs::read(&resolved).map_err(NiteraOperationError::Io)
    }

    /// Writes a file after policy authorization.
    ///
    /// The resolved location is authorized and written, so a symlinked or
    /// aliased path cannot write through to a denied file. A path that does
    /// not exist yet resolves through its deepest existing ancestor.
    pub fn write(
        &self,
        path: impl AsRef<std::path::Path>,
        content: impl AsRef<[u8]>,
    ) -> Result<(), NiteraOperationError> {
        let resolved =
            self.authorize_resolved(Operation::Write, path.as_ref(), true, |resolved| {
                NiteraRequest::filesystem(Operation::Write, resolved)
            })?;
        std::fs::write(&resolved, content).map_err(NiteraOperationError::Io)
    }

    /// Deletes a file after policy authorization.
    ///
    /// Only the parent is resolved. Unlinking a symlink removes the link
    /// rather than its target, so the final component is kept literal and
    /// the link's own location is what gets authorized.
    pub fn delete(&self, path: impl AsRef<std::path::Path>) -> Result<(), NiteraOperationError> {
        let resolved =
            self.authorize_resolved(Operation::Delete, path.as_ref(), false, |resolved| {
                NiteraRequest::filesystem(Operation::Delete, resolved)
            })?;
        std::fs::remove_file(&resolved).map_err(NiteraOperationError::Io)
    }

    /// Creates a new file at `path` with `content`.
    ///
    /// `content` accepts anything that converts to bytes, including `&str`, `String`, `&[u8]`,
    /// and `Vec<u8>`. Pass an empty value to create an empty file.
    /// The path is authorized against the `create` filesystem rules before the filesystem is
    /// touched. Creating an existing file returns `NiteraOperationError::AlreadyExists`.
    pub fn create(
        &self,
        path: impl AsRef<Path>,
        content: impl AsRef<[u8]>,
    ) -> Result<(), NiteraOperationError> {
        self.create_inner(path, CreateKind::File, Some(content.as_ref()))
    }

    /// Creates a new, single-level directory at `path`.
    ///
    /// The path is authorized against the same `create` filesystem rules as `create`. Creating
    /// an existing directory returns `NiteraOperationError::AlreadyExists`; a missing parent
    /// returns the underlying `Io` error.
    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<(), NiteraOperationError> {
        self.create_inner(path, CreateKind::Directory, None)
    }

    fn create_inner(
        &self,
        path: impl AsRef<Path>,
        kind: CreateKind,
        content: Option<&[u8]>,
    ) -> Result<(), NiteraOperationError> {
        // `create` never overwrites and `create_dir` makes exactly one
        // level, so the target is a new entry. Resolving the entry location
        // keeps the final component literal while still authorizing the real
        // parent directory, which is the resource the operation touches.
        let request_path =
            self.authorize_resolved(Operation::Create, path.as_ref(), false, |resolved| {
                NiteraRequest::create(resolved, kind)
            })?;

        let result = match content {
            Some(bytes) => std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&request_path)
                .and_then(|mut file| file.write_all(bytes)),
            None => std::fs::create_dir(&request_path),
        };

        result.map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                NiteraOperationError::AlreadyExists(request_path)
            } else {
                NiteraOperationError::Io(error)
            }
        })
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
        // A working directory is a location a child process actually runs
        // in, so it is authorized resolved rather than lexically. A
        // symlinked cwd inside an allowed scope must not reach a denied one.
        let request_cwd = resolve_aliases(&request_cwd).map_err(NiteraOperationError::Io)?;
        let request = NiteraRequest::process(&command, args.clone(), request_cwd.clone());
        // Authorize the resolved working directory, which is the directory
        // the child will actually run in.
        self.authorize_in_mode(&request, MatchMode::Resolved)?;
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

/// Whether `path` names a Nitera policy file.
///
/// Accepts either a `nitera` extension or a file named exactly
/// `.nitera`. `Path::extension` treats a leading dot as a hidden-file
/// marker rather than a separator, so `Path::new(".nitera").extension()`
/// is `None` and the dotfile form needs its own check.
fn has_nitera_extension(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("nitera")
        || path.file_name().and_then(|name| name.to_str()) == Some(".nitera")
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

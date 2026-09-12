#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilesystemRules {
    pub read: Vec<PathPattern>,
    pub write: Vec<PathPattern>,
    pub delete: Vec<PathPattern>,
    pub create: Vec<PathPattern>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilesystemPolicy {
    pub allow: FilesystemRules,
    pub ask: FilesystemRules,
    pub deny: FilesystemRules,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessPolicy {
    pub allow: Vec<String>,
    pub ask: Vec<String>,
    pub deny: Vec<String>,
    pub scope: Vec<PathPattern>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkPolicy {
    pub allow: Vec<HostPattern>,
    pub ask: Vec<HostPattern>,
    pub deny: Vec<HostPattern>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    pub filesystem: FilesystemPolicy,
    pub process: ProcessPolicy,
    pub network: NetworkPolicy,
}

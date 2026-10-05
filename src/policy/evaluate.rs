use super::model::{HostPattern, PathPattern, Policy};
use super::path::is_home_relative;
use crate::engine::{Decision, NiteraRequest, Operation, Resource, Target};
use std::path::Path;

impl Policy {
    fn evaluate_path(
        path: &Path,
        base: &Path,
        deny: &[PathPattern],
        ask: &[PathPattern],
        allow: &[PathPattern],
    ) -> Decision {
        let has_home_relative = deny
            .iter()
            .chain(ask)
            .chain(allow)
            .any(|pattern| is_home_relative(std::path::Path::new(&pattern.0)))
            || is_home_relative(path);
        if has_home_relative && std::env::var_os("HOME").is_none() {
            // A home-relative rule cannot be evaluated. Do not let a broad
            // allow match after an unresolved deny or ask has become a miss.
            return Decision::Deny;
        }

        if deny.iter().any(|pattern| pattern.matches_from(path, base)) {
            return Decision::Deny;
        }

        if ask.iter().any(|pattern| pattern.matches_from(path, base)) {
            return Decision::Ask;
        }

        if allow.iter().any(|pattern| pattern.matches_from(path, base)) {
            return Decision::Allow;
        }

        Decision::Deny
    }

    fn evaluate_host(
        host: &str,
        deny: &[HostPattern],
        ask: &[HostPattern],
        allow: &[HostPattern],
    ) -> Decision {
        if deny.iter().any(|pattern| pattern.matches(host)) {
            return Decision::Deny;
        }

        if ask.iter().any(|pattern| pattern.matches(host)) {
            return Decision::Ask;
        }

        if allow.iter().any(|pattern| pattern.matches(host)) {
            return Decision::Allow;
        }

        Decision::Deny
    }

    pub fn evaluate(&self, request: &NiteraRequest, base: &Path) -> Decision {
        match (&request.resource, &request.operation, &request.target) {
            (Resource::Filesystem, Operation::Read, Target::Path(path)) => Self::evaluate_path(
                path,
                base,
                &self.filesystem.deny.read,
                &self.filesystem.ask.read,
                &self.filesystem.allow.read,
            ),

            (Resource::Filesystem, Operation::Write, Target::Path(path)) => Self::evaluate_path(
                path,
                base,
                &self.filesystem.deny.write,
                &self.filesystem.ask.write,
                &self.filesystem.allow.write,
            ),

            (Resource::Filesystem, Operation::Delete, Target::Path(path)) => Self::evaluate_path(
                path,
                base,
                &self.filesystem.deny.delete,
                &self.filesystem.ask.delete,
                &self.filesystem.allow.delete,
            ),

            (Resource::Filesystem, Operation::Create, Target::Create { path, kind: _ }) => {
                Self::evaluate_path(
                    path,
                    base,
                    &self.filesystem.deny.create,
                    &self.filesystem.ask.create,
                    &self.filesystem.allow.create,
                )
            }

            (
                Resource::Process,
                Operation::Execute,
                Target::Process {
                    command,
                    args: _,
                    cwd,
                },
            ) => {
                if std::env::var_os("HOME").is_none()
                    && (is_home_relative(cwd)
                        || self
                            .process
                            .scope
                            .iter()
                            .any(|scope| is_home_relative(std::path::Path::new(&scope.0))))
                {
                    return Decision::Deny;
                }

                if !self
                    .process
                    .scope
                    .iter()
                    .any(|scope| scope.matches_from(cwd, base))
                {
                    return Decision::Deny;
                }

                if self.process.deny.iter().any(|cmd| cmd == command) {
                    return Decision::Deny;
                }

                if self.process.ask.iter().any(|cmd| cmd == command) {
                    return Decision::Ask;
                }

                if self.process.allow.iter().any(|cmd| cmd == command) {
                    return Decision::Allow;
                }

                Decision::Deny
            }

            (Resource::Network, Operation::Connect, Target::Network { host, port: _ }) => {
                Self::evaluate_host(
                    host,
                    &self.network.deny,
                    &self.network.ask,
                    &self.network.allow,
                )
            }

            _ => Decision::Deny,
        }
    }
}

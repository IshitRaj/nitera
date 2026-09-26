# Security and hardening audit, 1.0.0

**Status: items 6, 12, and 16 are fixed on `main`, but unreleased as of
the reviewed base `0a9367f` (2026-09-26).** Items 1, 2, and 18 remain
confirmed policy bypasses. Item 18 is another instance of unresolved
filesystem aliases, not an independent vulnerability class.

This document records findings and a corrected remediation plan. Updating
the document does not fix the implementation. The original audit targeted
the 1.0.0 source at `d730383`; commit `a09590a`, merged through PR #3,
fixed the three items above. The fixed status refers to source on `main`,
not the published 1.0.0 crate. Each implementation PR must update its own
status and link its regression coverage; a release must record the first
published version containing the fix.

## Evidence and limits

An independent review of `d730383` built the crate and ran its existing
suite: 149 tests passed. Separate local probes on a case-insensitive macOS
filesystem nevertheless returned synthetic protected data through an
allowed symlink, differently cased path, and `/tmp` alias. The probes also
checked parser behavior, ignored arguments and ports, inherited environment,
missing `HOME`, dotfile rejection, single-level directory creation, and
the contradictory example policy. No real secrets or external network
connections were needed. Those probes were outside the repository; each
fix needs committed regression tests rather than relying on this record.

The current source includes the three fixes and the test-fixture cleanup
from PR #5. The source changes since the independently tested audit commit
do not change the path bypasses. Windows behavior is supported by code
inspection only; it has not been runtime-verified in this review.

The 375 ns median at 1,000 rules in `BENCHMARKS.md` is a historical M2
release-build measurement of the existing `check()` workload. It is not a
measurement of any proposed fix or an end-to-end filesystem operation.
Costs below identify where work occurs; they are not measured latency
claims. No fix is assumed to have zero cost merely because it allocates
nothing, and no fixed syscall count is assumed for canonicalization.

## Threat model

Nitera mediates operations that an application explicitly routes through
its API. The relevant attacker can supply paths, commands, or hosts to
that application; some scenarios also allow them to alter filesystem
entries or influence the child-process environment. A wrapper must not
authorize one name and access a different, denied resource.

Nitera is not a sandbox for arbitrary hostile code in its own process.
Such code can call operating-system APIs directly. Allowed child processes
are not confined by Nitera's filesystem or network rules either. Fixing
path authorization does not change those limits. Approval handlers make
decisions; they do not provide operating-system isolation.

Distinguish static alias attacks from concurrent filesystem replacement.
Resolving a path and subsequently opening it can mitigate static aliases,
but a separate check and syscall leave a TOCTOU race. Do not describe that
partial mitigation as safe against an attacker who can replace directory
entries between authorization and use.

## Verification summary

Numbering matches the detailed findings and sequencing table.

| # | Finding | Class | Evidence | Status |
|---|---|---|---|---|
| 1 | Symlink traversal bypasses narrow allows and explicit denies | security | protected synthetic payload returned | open |
| 2 | Case-insensitive filesystem names bypass case-sensitive denies | security | protected synthetic payload returned on macOS | open |
| 3 | Windows path representation and HOME assumptions | correctness | source inspection; Windows execution required | open |
| 4 | Commas cannot be represented literally in values | grammar limitation | parser output verified | open |
| 5 | Hashes start comments even inside intended paths | grammar limitation | parser output verified | open |
| 6 | Repeated whitespace between action and kind breaks parsing | correctness | original error reproduced; regression tests added | fixed, unreleased (#3) |
| 7 | Process arguments are not evaluated | model gap | policy decisions verified | open |
| 8 | Network ports are not evaluated | model gap | decisions for several ports verified | open |
| 9 | Child environment and executable lookup are inherited | model gap | synthetic environment inheritance verified; lookup inspected | open |
| 10 | Filesystem operation coverage is incomplete | model gap | public API inspected | open |
| 11 | create_dir creates only one level | feature limitation | missing-parent error verified | open |
| 12 | Bare .nitera filename rejected by load | correctness | original error reproduced; regression test added | fixed, unreleased (#3) |
| 13 | HOME required for ordinary filesystem/process paths | robustness | isolated missing-HOME probe | open |
| 14 | Denied error does not carry the request | auditability | error representation inspected | open |
| 15 | Public types have compatibility constraints on extension | API evolution | type definitions inspected | open |
| 16 | Nitera lacks Debug in 1.0.0 | ergonomics | implementation and regression test reviewed | fixed, unreleased (#3) |
| 17 | Normalization errors become nonmatching patterns | latent hardening concern | missing-HOME scenario fails closed | open; no demonstrated bypass |
| 18 | /tmp versus /private/tmp alias can bypass a deny | security, related to #1 | protected synthetic payload returned | open |
| 19 | Example host allow is overridden by deny host * | documentation | resulting Deny verified | open |

## Security and platform correctness

### 1. Symlink traversal

`normalize_path` is lexical. `Nitera::read` and other wrappers authorize
the unresolved path and pass it to the operating system, which follows
symlinks. With `allow read ./allowed/**` and `deny read ./Secrets/**`,
an `allowed/escape -> ../Secrets` link lets `read("./allowed/escape/key")`
return the protected payload while `read("./Secrets/key")` is denied.

**Corrected approach.** Define a shared, operation-aware path authorization
layer for guarded filesystem operations and process working directories.
Resolve request paths and literal policy anchors consistently; normalizing
requests alone can leave denies attached to an alias that never matches.
Do not canonicalize an entire wildcard string as if it were a filename.
Specify how wildcard portions interact with aliases, and reject unsupported
policy/topology combinations instead of silently discarding deny rules.

For an existing read/write target, authorize the resolved target. For a
new entry, resolve and authorize its parent plus the final component;
keep exclusive creation and reject dangling-link or unsupported-parent
cases explicitly. Do not blindly canonicalize the final component for
`delete`: removing a symlink is different from deleting its target.
Working-directory authorization must address symlink aliases as well.

Keep lexical `check()` documented as advisory unless it is deliberately
changed to perform resolution. Guarded methods must use the resolved,
fallible authorization path themselves, not trust an earlier lexical
verdict. Resolution failures must stop the operation, never fall back to
the unresolved name. Any optional lexical-only mode must be explicitly
advisory; it cannot serve as the hardened default for guarded operations.

Canonicalizing an existing ancestor and appending a missing tail is only
a static-alias mitigation. Concurrent replacement requires an appropriate
handle/capability-based backend that ties authorization to the resource
actually used. Evaluate platform primitives or a maintained capability
library; merely adding a dependency or a canonicalize call is not proof
of race resistance. Either implement and test that boundary or explicitly
exclude attacker-writable namespace races from the supported guarantee.

**Required checks.** Existing file and directory symlinks, explicit denies,
relative and absolute policy anchors, symlinked working directories,
missing parents, dangling links, symlink loops, and delete-link versus
delete-target behavior. For a race-resistant claim, include adversarial
replacement tests against the selected backend. Include item 18's probe.

**Cost and scope.** Filesystem resolution adds I/O and varies with platform,
path depth, caches, and filesystem. Rust's `canonicalize` uses Unix
`realpath` or Windows APIs; one Rust call is not a guarantee of one syscall.
Measure end-to-end guarded operations separately from lexical `check()`.
This is a substantial security change, not a one-helper patch.

### 2. Case-folding and equivalent filesystem names

With `deny read ./Secrets/**` and `allow read ./**`, requesting
`./secrets/key` returned the protected payload on a case-insensitive
volume. An attacker can choose the alternate spelling; the policy author
does not have to mistype the rule. No new symlink is required.

**Corrected approach.** Use the relevant filesystem's name-equivalence
semantics in the path authorization layer, with explicit supported-platform
and topology guarantees. A flag obtained by creating one file at the policy
root does not cover absolute paths on other volumes, mounted subtrees,
read-only roots, or directory-specific Windows case sensitivity. Probe
failure must never silently select case-sensitive enforcement.

Both the public matcher and the loaded policy's prepared matcher must
implement the same semantics. `PreparedPath` performs its own equality,
byte checks, prefix stripping, and glob comparisons. `PathSet` sorts and
selects candidates with byte-sensitive comparisons. Updating only
`component_matches` leaves the normal loaded-policy path vulnerable.
The index must not exclude any candidate that the final matcher could
match; disable an incompatible optimization until it is correct.

Do not lowercase every path globally: that can broaden allow rules on a
case-sensitive filesystem. `eq_ignore_ascii_case` is only an ASCII subset,
not Windows or macOS filesystem equivalence. Unicode normalization and
case handling are platform/filesystem concerns, not a problem solved by
arbitrary locale-sensitive lowercasing. Reject unsupported cases in a
hardened mode rather than declaring an ASCII-only mitigation complete.

**Required checks.** Exact, subtree, and wildcard deny/ask/allow patterns;
small scans and indexed sets with at least 64 diverse rules; alternate
ASCII casing; non-ASCII and normalization-equivalent names where supported;
case-sensitive directories; read-only roots; and mixed-volume paths.
Check results against actual filesystem identity as well as parity between
public and prepared evaluators. Two matching implementations can share a bug.

**Cost and scope.** Unmeasured. Comparison, key preparation, platform queries,
and index design can affect load time and checks. This depends on item 1's
path model and requires platform-specific tests, not a one-function fix.

### 3. Windows path handling

`normalize_pattern` splits on `/` and constructs a leading `/`, whereas
Windows paths can contain backslashes, drive/UNC prefixes, and extended
path syntax. Request and pattern representations can consequently differ.
The unconditional HOME requirement is another obstacle. These findings are
from source inspection; Windows support needs execution on a Windows host.

**Corrected approach.** Define a platform-aware internal path representation
used by both patterns and requests. Preserve drive and UNC identity;
distinguish drive-relative, rooted, absolute, and extended-length paths.
Separator conversion may be part of that boundary, but cannot replace
prefix semantics. Reject unsupported namespaces explicitly. Never convert
backslashes on Unix, where they can be literal filename characters.
Integrate platform case behavior and item 13's home-directory handling.

**Required checks.** A Windows CI runner covering drive-relative and absolute
paths, mixed separators, UNC and extended paths, traversal, missing HOME,
and case-sensitive directories. Verify checks and real guarded operations.
Costs are unmeasured; per-request conversion is runtime work.

## Policy grammar

### 4. Commas in paths

`parse_values` splits `./a,b/**` into `./a` and `b/**`. That follows the
current comma-list grammar, but cannot express the intended literal path.
A mistaken deny may leave data accessible under another allow.

### 5. Hashes in paths

The comment pass turns `./a#b/**` into `./a`. This is documented syntax,
but there is no literal escape. Items 4 and 5 are expression limitations
with potential policy consequences, not corruption of every valid policy.

**Corrected approach for 4 and 5.** Add a quote-aware lexer before comment
removal. Split commas and recognize comments only outside quoted values;
support explicit escapes for quotes and backslashes and reject malformed
input with line information. Keep spaces within a quoted value intact.
Changing only `parse_rule` or `parse_values` is insufficient because
`parse()` currently strips comments first.

Use an explicit grammar-version/migration decision: existing bare values
can contain quote characters literally. Do not promise universal backward
compatibility while reinterpreting those values. Preserve legacy parsing
where promised and reject unsupported new syntax clearly.

**Required checks.** Quoted commas, hashes, spaces, empty values, escaped
quotes/backslashes, mixed quoted/unquoted lists, comments after values,
unbalanced quotes, and legacy values containing quote characters. Verify
resulting deny/ask/allow decisions, not just successful parsing.
Parsing costs occur at load time; benchmark unusually large policies if
needed. Existing checks need not gain extra parsing work.

### 6. Whitespace between action and kind — fixed, unreleased

The 1.0.0 `splitn(3, char::is_whitespace)` parser rejects `allow  read ./a`
because it produces an empty kind. This fails parsing; unlike items 4 and
5, it does not silently accept a different policy.

Commit `a09590a` extracts the first two fields while skipping separators,
then preserves the complete remainder as the values field. Keep that fix.
Do not substitute `split_whitespace().take(3)`: it loses `./b` and `./c`
from `deny read ./a, ./b, ./c`, potentially weakening the deny.

**Coverage to preserve.** Repeated spaces, mixed tabs/spaces, missing kind,
and comma-separated values with spaces. Track the first released version;
no replacement implementation is needed.

## Model and API extensions

### 7. Process arguments are not evaluated

Both evaluators authorize command names and working-directory scope, not
arguments. `git -c core.pager=sh log` receives Allow under `allow command
git`; that verdict does not prove this exact command launches a pager in
every environment. General interpreters/build tools can execute arbitrary
code, and an allowed process can access resources outside Nitera wrappers.

**Corrected approach.** Add an explicit, versioned command-rule form that
can match a command identity and exact argv vectors. Do not reinterpret
`allow command git status, diff`: today it names two commands, `git status`
and `diff`. Preserve unrestricted legacy command rules as unrestricted.
A narrower allow does not constrain a coexisting unrestricted allow;
migration must remove broad grants when restrictions are intended.

Apply deny, then ask, then allow across applicable rules, and enforce cwd
scope independently. Define no-argument and empty-argument behavior without
joining argv into a shell string. Argument restrictions do not sandbox an
allowed program's descendants or inputs. Coordinate executable identity
with item 9.

**Required checks.** Exact vectors, empty arguments, executable mismatch,
command-level deny overriding argument-level allow, ask precedence, broad
legacy allows, and out-of-scope cwd. Argument matching adds runtime work;
measure it rather than calling it free.

### 8. Network ports are not evaluated

`allow host api.github.com` permits any port at the policy layer. Local
probes confirmed Allow for 22, 443, 5432, and 6379 without opening sockets.

**Corrected approach.** Add an unambiguous endpoint rule with optional port
constraints; preserve legacy host-only rules as any-port grants. Define
numeric ranges and IPv6 bracket syntax explicitly, and match host plus
port in both policy paths. Define hostname equivalence as well: DNS names
are not byte-case-sensitive, and alternate spelling must not skip a deny.
Do not turn a hostname allow into an implied IP-address or protocol policy.

Hostname authorization alone does not filter resolved addresses, including
loopback/private addresses. Address restrictions, if promised, must resolve,
validate, and connect to the selected address without a second resolution.
The returned `TcpStream` has no application-protocol policy. It does not
automatically follow HTTP redirects; an application must authorize any
new redirected connection separately.

**Required checks.** Allowed/disallowed ports, legacy any-port behavior,
precedence, invalid ranges, IPv6, hostname casing, and controlled local
connections. Port checks add small but nonzero work. DNS/address enforcement
is a separate capability and needs its own tests and measurements.

### 9. Environment and executable lookup

`execute` inherits environment variables and uses `Command::new` lookup.
A synthetic variable was visible to an allowed child. An attacker who
controls PATH can influence which executable a bare command name selects.

**Corrected approach.** Offer an explicit child-environment policy with a
documented base environment and allow/deny lists. Construct children using
`env_clear` plus approved entries. Preserve legacy inheritance behind an
explicit compatibility mode or make the changed default a major-version
decision. Do not expose variable values in audit logs by default.

Executable resolution must also be specified: bind rules to approved
absolute executables, or resolve through a fixed trusted search path and
authorize that result. Environment filtering alone does not establish
executable identity. Do not mutate the host process's global environment
to launch a child.

**Required checks.** Synthetic secrets, allow/deny collisions, missing PATH,
a test executable shadowing a trusted name, absolute executables, required
platform environment variables, and unchanged parent environment.
Environment assembly affects launch cost, not merely policy parsing.

### 10. Missing filesystem wrappers

The guarded API includes read, write, delete, create, and create_dir. It
has no separate read_dir, rename, copy, symlink, metadata, or append API.
`write` already truncates existing files. A missing wrapper is an API gap,
not a demonstrated bypass through an existing method; direct `std::fs`
access has always been outside this library's mediation.

**Corrected approach.** Add explicit operation semantics incrementally.
Listing requires authorization for the directory; metadata must specify
whether links are followed. Rename requires source and destination rules
and an explicit replacement policy. Copy requires source-read and
destination-write/create permissions. Reuse the resolved authorization
layer and propagate deny/ask decisions for every affected resource before
performing an operation. Do not silently bypass denied destinations.

**Required checks.** Source/destination combinations, existing-target
replacement, cross-filesystem errors, aliases, and unresolved approvals.
Existing methods need not change cost; each new method has its own checks.

### 11. Recursive directory creation

`create_dir` is deliberately single-level; a missing parent yields an I/O
error. Adding `create_dir_all` is a feature, not a correction to that API.

**Corrected approach.** Authorize every missing directory the operation
would create. Authorizing only the deepest path is insufficient: default
deny cannot protect intermediate mutations that are never checked.
Resolve existing ancestors using item 1's rules, keep creation relative
to the authorized parent, and define behavior under concurrent changes.
Specify partial success and approval behavior; do not imply atomicity or
remove directories that another actor may now be using during rollback.

**Required checks.** Denied intermediate ancestor with allowed leaf,
existing parents, per-level ask decisions, file/link collisions, and a
failure after one directory was created. Work scales with depth.

## Robustness and compatibility

### 12. Dotfile policy loading — fixed, unreleased

In 1.0.0, the extension guard rejects `.nitera` because a leading dot does
not constitute a file extension. Commit `a09590a` accepts either the exact
filename `.nitera` or an extension of `nitera`, retaining rejection of
`.nitera.bak` and unrelated extensions. Preserve that implementation and
its tests; record the first release containing it. The original README
example failed at this loading step, regardless of its other prerequisites.

### 13. HOME required without tilde expansion

Filesystem and process path resolution require HOME even for ordinary
paths. With HOME absent, guarded reads return an I/O error and checks deny.
Network checks do not have this dependency, so the entire crate is not
uniformly unusable without HOME.

**Corrected approach.** Resolve home only for a supported home-relative
form (`~` or `~/...`, plus explicitly defined platform equivalents).
Separate pattern and request resolution from unconditional environment
lookup. Define a platform home-provider contract rather than assuming
Windows always supplies HOME.

Crucially, an unresolved home-relative deny must not become a nonmatch
while an ordinary allow starts working. Reject such a policy at load, or
return an authorization error/Deny when it cannot be evaluated. Preserve
the current documented response to HOME changes, or introduce an explicit
versioned immutable-home contract; do not accidentally freeze old denies.
Review item 17 in the same change.

**Required checks.** HOME absent with ordinary rules; absent with a
home-relative deny plus broad allow; set, unset, or changed after loading;
and public/prepared evaluator parity. Run environment changes in isolated
processes. Any speedup remains unmeasured.

### 14. Denied errors lack request context

`NiteraOperationError::Denied` is fieldless; `Ask` carries a `NiteraRequest`.
Applications can log their inputs, but the denied error alone cannot
identify the operation.

**Corrected approach.** For a compatible extension, add an optional audit
callback that receives the request and decision before the context is
discarded. Define privacy, callback failure, and reentrancy behavior. An
error-carried request is an alternative for a deliberate breaking API
release, with migration examples.

Adding `DeniedRequest(NiteraRequest)` is not source-compatible with
downstream exhaustive matches. A `request()` accessor on the current
fieldless `Denied` can only return None; it cannot recover discarded data
and is not a fix by itself. The request type is `NiteraRequest`.

**Required checks.** Denied operation context, approval denial, no callback
on unrelated operations, and documented logging/redaction behavior.
Callbacks and any request copies add runtime cost; measure if enabled.

### 15. Public type evolution

Public exhaustive enums make new variants a breaking change. Adding
`#[non_exhaustive]` now also breaks external exhaustive matches. This is
an API design decision, not a current security vulnerability.

**Corrected approach.** Review NiteraError, NiteraOperationError, Decision,
Resource, Operation, CreateKind, and Target individually in a major-version
plan. `ParseError` is a struct: applying the attribute also affects external
construction and destructuring. Do not blanket-annotate public types or
label a breaking release safe because adoption is small.

**Required checks.** Downstream compile examples for matching, construction,
and migration, alongside release notes. This attribute itself does not add
runtime matching work.

### 16. Debug — fixed, unreleased; Clone is separate

Commit `a09590a` adds a manual Debug implementation that exposes the policy
root and handler-registration state without formatting the handler or
prepared policy. Preserve it and the regression coverage. PR #5 also
cleans up both temporary policy files used by the test.

`Arc<dyn ApprovalHandler>` does not inherently prevent Clone: cloning an
Arc shares the allocation without requiring the handler to implement
Clone. PreparedPolicy currently lacks Clone. Adding Clone is a separate
feature that must define whether policy state and callbacks are shared;
it is unnecessary to implement Debug.

### 17. Normalization failure and fail-closed behavior

PreparedPath uses `Tail::Never` on normalization failure and public
PathPattern matching returns false. That representation is a hardening
concern if a failed deny can coexist with a successful allow.

The tested missing-HOME scenario is not currently a demonstrated bypass.
While HOME is absent, path authorization fails closed; if HOME changes,
PreparedPolicy deliberately falls back to the source evaluator. This is
documented and tested behavior, not protection established only by accident.

**Corrected approach.** Preserve those guarantees while changing item 13.
Prefer fallible policy preparation that rejects unresolved enforcement
rules, with contextual diagnostics. A future fallible public matcher must
propagate errors through evaluators as denial/failure, not `unwrap_or(false)`
for deny lists. A warning alone is insufficient if a deny becomes inactive.
Assess the API compatibility of returning Result before changing it.

**Required checks.** An invalid/unresolved deny plus a broad allow must
never return Allow in either evaluator, including after environment changes.

### 18. macOS /tmp aliases can bypass deny rules

The loader canonicalizes a policy's parent, but ordinary absolute request
paths are matched lexically. This can cause false denials under narrow
allows and can also fail open under broader allows. It is not merely a
documentation issue.

The following policy was tested under `/tmp/<fixture>/policy.nitera`:

```text
[filesystem]
allow read /**
deny read ./**
```

The root becomes `/private/tmp/<fixture>`. Reading `./key` is denied;
reading `/tmp/<fixture>/key` returns the same synthetic protected payload.
The alias skips the canonical-root deny and matches the broad allow.

**Corrected approach.** Include this in item 1's shared alias-resolution
work. Canonicalize compatible policy anchors and authorize the resource
actually used; do not rely on users spelling every alias canonically.

**Required checks.** Both spellings, relative and absolute denies, broad
allows, and supported operations. Run the actual alias case on macOS and
an explicit directory-symlink analogue where the /tmp alias is absent.

### 19. Contradictory example policy

`examples/playground.nitera` contains `allow host api.github.com` followed
by `deny host *`. Since deny wins, the allow is ineffective. The filename
is `.nitera`, not `.nitersa`.

**Corrected approach.** If the example is intended to allow GitHub, remove
the catch-all deny and rely on default deny for unmatched hosts. Otherwise
remove the ineffective allow and explain the all-denied example. Keep the
example and its narrative consistent. Verify GitHub and an unmatched host
with local policy checks; no external connection is needed.

## Separate feature requests

- Handler replacement is an API/lifecycle choice. A setter taking `&mut
  self` does not by itself allow replacement through shared Arc references.
- Reload/watch support needs explicit snapshot and concurrent-reader
  semantics; existing snapshot behavior is documented, not a defect.
- Blocking operations can use a blocking pool from async applications.
  Timeouts, cancellation, bounded output, and native async support are
  separate features; lack of an async API does not make every use invalid.

## Implementation order and acceptance gates

Keep fixes independently reviewable, but do not split a security invariant
across changes that temporarily allow requests the policy should deny.

| Order | Items | Deliverable and acceptance gate |
|---|---|---|
| Already merged | 6, 12, 16 | Preserve fixes from #3 and test cleanup from #5; track release status. |
| 1 | 1, 2, 3, 18 | Commit isolated bypass regressions and a platform/path semantics contract; distinguish static-alias mitigation from race resistance. |
| 2 | 1, 18 | Implement shared, operation-aware resolved authorization; pass symlink, alias, creation, deletion, and cwd checks; benchmark guarded operations. |
| 3 | 2, 3 | Enforce supported filesystem name equivalence through both matchers and candidate indexes; reject unsupported enforcement modes; run platform tests. |
| 4 | 13, 17 | Remove unnecessary home lookup without permitting unresolved deny rules; pass isolated environment-transition tests. |
| 5 | 4, 5 | Approve a versioned quote/escape grammar; preserve or explicitly migrate legacy values; pass parsing and decision regressions. |
| 6 | 19 | Correct the example and verify intended host decisions. This independent docs fix may land earlier. |
| 7 | 14, 15 | Choose compatible audit events or a breaking error/type release, with downstream migration tests. |
| 8 | 7, 8, 9 | Add explicit argv, endpoint, environment, and executable semantics; preserve legacy unrestricted grants unless a migration changes them. |
| 9 | 10, 11 | Add filesystem operations with every affected resource authorized, after the shared path layer is ready. |

Path fixes must carry tests for the bypasses they claim to close, plus
negative cases proving legitimate denies remain effective. A green existing
suite is not sufficient: all 149 original tests passed while the bypasses
were reproducible. Platform-specific tests must report skipped coverage
honestly rather than treating it as a successful security verification.

Measure lexical checks, preparation, and end-to-end guarded operations
separately. Record workload, platform/filesystem, build profile, and cache
conditions. Do not promise +1–2 microseconds, one syscall, zero overhead,
or unchanged latency before measuring the actual implementation.

## References and reporting

- [Original audit commit](https://github.com/IshitRaj/nitera/commit/d73038332382140773f76ee0beee23a11d8024a6)
- [Three merged fixes](https://github.com/IshitRaj/nitera/commit/a09590af4ebdcb62881ff8ef1c9d073839b02e92)
- [Rust canonicalize platform behavior](https://doc.rust-lang.org/stable/std/fs/fn.canonicalize.html)
- [Windows per-directory case sensitivity](https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity)
- [Arc cloning semantics](https://doc.rust-lang.org/std/sync/struct.Arc.html)

Report additional findings with the exact revision, policy, platform and
filesystem, expected decision, actual decision/operation result, and a
minimal synthetic reproduction. Findings and proposals remain open to
correction. Link fixed items to committed regression tests and identify
unsupported threat models explicitly.

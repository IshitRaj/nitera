# Security and hardening audit, 1.0.0

**Status: 3 of 19 fixed on `main`, none released yet.** The two
confirmed bypasses, items 1 and 2, are still open. `nitera 1.0.0` on
crates.io has every finding below, including the three marked fixed,
which are on `main` and unreleased.

The Status column tracks fixes in place, and each fix PR flips its own
row in the same commit that lands it. Anything marked "fixed,
unreleased" is on `main` but not in a published version.

Both of those reproduce, and return the payload. A caller behind a
narrow `allow` plus a broad `deny` can be made to read a protected
file, and the second needs nothing created on disk at all. Details are
in the sections below.

Fixes are landing as separate, independently reviewable PRs. The
sequencing table at the end gives the intended order. The findings
themselves are not up for debate.

Every claim here was checked by reading the code and, where marked
"verified", by running a throwaway program against the v1.0.0 checkout.
Those probe crates were deleted and are not part of the repository.

Latency figures refer to the baseline in `BENCHMARKS.md`: 375 ns median
for `check()` at 1,000 rules, on an M2, release profile. Exactly one
item in this audit moves that number, and it says so when you reach it.

## Verification summary

Numbering here matches the section headings below, which is what the
sequencing table at the end refers to.

| # | Finding | Class | How confirmed | Status |
|---|---|---|---|---|
| 1 | Symlink traversal bypasses narrow patterns and explicit denies | security | verified, payload returned | open |
| 2 | Case-folding bypass on case-insensitive filesystems | security | verified, payload returned | open |
| 3 | Windows path handling is broken | correctness | code inspection, needs a Windows host | open |
| 4 | Comma in a path silently splits into two patterns | correctness | verified | open |
| 5 | `#` in a path silently truncates the rule | correctness | verified | open |
| 6 | Double space between action and kind breaks parsing | correctness | verified | fixed, unreleased |
| 7 | Process arguments are not evaluated | model gap | verified | open |
| 8 | Network port is not evaluated | model gap | verified | open |
| 9 | Environment is inherited wholesale and is not policy-able | model gap | verified | open |
| 10 | `read_dir`, `rename`, `copy`, symlink and metadata are not covered at all | model gap | verified | open |
| 11 | `create_dir` is single level, with no `create_dir_all` | ergonomics | verified | open |
| 12 | `Nitera::load(".nitera")` always fails | bug | verified | fixed, unreleased |
| 13 | `HOME` is required even when no rule uses `~` | robustness | verified | open |
| 14 | `NiteraOperationError::Denied` carries no request | auditability | verified | open |
| 15 | Public enums are not `#[non_exhaustive]` | evolution | verified | open |
| 16 | `Nitera` derives nothing, so no `Debug` | ergonomics | verified | fixed, unreleased |
| 17 | Normalization failure becomes a silent never-match rule | latent | verified masked | open |
| 18 | macOS `/tmp` versus `/private/tmp` aliasing | footgun | code inspection | open |
| 19 | `examples/playground.nitersa` has a dead `allow host` line, see docs below | docs | verified | open |

## P0, security bypasses

### 1. Symlink traversal

`normalize_path` in `src/policy/path.rs` is documented as purely lexical
with no filesystem access, and `Nitera::read` and friends pass the same
unresolved string to both the policy check and the underlying syscall.
A symlink inside an allowed directory therefore points outside it, and
the check never sees the difference.

Verified with a policy of `allow read ./allowed/**` plus an explicit
`deny read ./secret/**`, and a symlink `allowed/escape -> secret`:

```
check() verdict: Allow
read() SUCCEEDED, returned: TOP SECRET KEY MATERIAL
```

The explicit deny did not fire. `README.md` currently describes this as
"not currently handled as a separate security boundary", which
understates it: it defeats the narrow `allow` patterns that
`DOCUMENTATION.md` correctly identifies as the actual security boundary.

**Approach.** Resolve the deepest existing ancestor of the request path
with a single `canonicalize`, then re-append the non-existent tail. This
is the standard realpath technique, it works for paths that do not exist
yet (which `create` requires), and it needs no new dependency.

**Cost.** One filesystem syscall per filesystem operation, so roughly
1 to 2 microseconds added to a check that currently costs 375 ns. That
is real, and it is the one place in this plan where latency genuinely
moves. Two mitigations:

- The guarded syscall it protects (`open`, `read`, `write`) already costs
  single-digit microseconds, so the overhead stays well under the cost of
  the operation being guarded.
- Gate it behind a policy directive rather than a compile-time feature, so
  a caller who only needs `check()` semantics can opt out and keep the
  fast path. Suggested grammar, added to the existing section model:

  ```text
  [security]
  resolve_symlinks = true
  ```

  Default `true`, because a security control that is off by default is
  not a control. A `false` value is only defensible for callers that treat
  the policy as advisory.

**Complexity.** Low to moderate. The resolution helper is self-contained
and unit-testable. The risk is introducing a TOCTOU window between
resolve and open, which already exists today in a worse form; the honest
position is that this narrows the window, it does not close it. Closing
it properly needs descriptor-relative syscalls, which is `cap-std`'s job,
not this crate's.

**Benchmark consequence.** `BENCHMARKS.md` will need a second harness that
measures authorize-plus-resolve, not just `check()`. Reporting a single
375 ns number once resolution is in the path would be misleading. This
should be done in the same PR as the fix, not deferred.

### 2. Case-folding bypass

`component_matches` in `src/policy/matcher.rs` is byte-exact
(`pattern == value`), while macOS filesystems are case-insensitive by
default and Windows always is. A deny written with different
capitalization than the caller's path does not match, while a broad
allow does, and the filesystem opens the real file.

Verified on a case-insensitive volume with `deny read ./Secrets/**` plus
`allow read ./**`:

```
check() -> Allow
read() -> Ok, returned: CASING BYPASS PAYLOAD
```

This is arguably the more dangerous of the two, because it needs no
attacker-created filesystem object. It only needs a policy author to
write `.SSH` where the caller writes `.ssh`, which is an everyday
mistake.

**Approach.** Detect case sensitivity once, at load, by writing a probe
file and checking whether a case-flipped name resolves. Store the result
on the prepared policy. Then compare with `eq_ignore_ascii_case` when
insensitive.

**Cost.** Effectively zero. `eq_ignore_ascii_case` allocates nothing, and
the detection is one extra file create plus stat at load time, not per
check.

**Complexity.** Low, and it is a small localized change to one function
plus a flag threaded through. This is the best ratio in the whole plan.

**Known limit to document.** ASCII case folding is not full Unicode case
folding. It closes the realistic bypasses (`.SSH`, `Secrets`, `README`)
and matches Windows' ordinal-ignore-case model. macOS performs Unicode
normalization, so exotic cases involving combining marks remain open.
Documenting that is honest; solving it needs locale-aware folding, which
is a large dependency and a genuine complexity spike, so it is out of
scope.

### 3. Windows path handling

`normalize_pattern` splits the pattern string on `/` and rebuilds it as
`format!("/{}", ...)`, and the prepared matcher splits and joins on `/`
as well. On Windows, `to_string_lossy()` yields `\`, so an absolute
pattern collapses into a single component and gains a spurious leading
`/`, which cannot match a request path produced the same way.

Combined with finding 11 (`HOME` is required unconditionally, and Windows
routinely has no `HOME`), the practical result is that Windows is
unsupported today, while `src/policy/path.rs` contains explicit
`#[cfg(not(unix))]` branches implying otherwise.

**Approach.** Normalize separators once at the boundary (`\` to `/` on
Windows, before pattern and request processing) so the rest of the engine
keeps a single canonical form. That is a smaller change than making the
whole engine separator-agnostic.

**Cost.** Zero per check. The conversion happens at load for patterns and
once per request for paths, and the request path is already being turned
into a `String`.

**Complexity.** Moderate, and it cannot be validated properly without a
Windows CI runner. That is the main blocker, not the code.

## P1, silent policy corruption

All three produce a policy that is accepted, is different from what was
written, and reports no error. A corrupted `deny` is a fail-open.

### 4. Comma in a path

`parse_values` splits on commas and drops empties, so
`allow read ./a,b/**` parses successfully as two patterns, `./a` and
`b/**`. Verified. A path containing a comma cannot be expressed, and the
mistake is silent.

### 5. `#` in a path

The comment strip runs before rule parsing, so `allow read ./a#b/**`
parses as `./a`. Verified. A `deny` written this way is silently weaker
than intended. This is documented, but "you cannot express this" and
"this silently changes your policy" are very different failure modes.

**Approach for 4 and 5 together.** Add a single explicit quoting rule to
the format rather than two special cases: a value may be wrapped in
double quotes, in which case it is taken verbatim with no comma splitting
and no comment stripping. That is one small change in `parse_rule` and
`parse_values`, it is backwards compatible because bare values keep
current behavior, and it gives an escape hatch for both problems plus any
future one. Reject unbalanced quotes with a `ParseError` naming the line.

**Cost.** Zero per check, since quoting is resolved at parse time and the
prepared representation is unchanged.

**Complexity.** Low. The risk is under-testing, so the PR needs parser
tests for quoted commas, quoted hashes, spaces inside quotes, and
unbalanced quotes.

### 6. Double space between action and kind

`parse_rule` uses `splitn(3, char::is_whitespace)`, which yields an empty
middle field for `allow  read ./a`, producing
`line 2: unknown filesystem operation: ` with a blank name. Verified.
Tabs, leading indentation, and a double space before the value all work
correctly, so this is one narrow hole rather than a general fragility.

**Approach.** Replace `splitn(3, char::is_whitespace)` with
`split_whitespace().take(3)`, or filter empty fields before indexing.
This also deletes code rather than adding it.

**Cost.** Zero. **Complexity.** Trivial. This should be its own small PR
because it is a three-line change with no interaction with anything else
in this plan.

## P2, model gaps

These are feature gaps rather than defects. Each one widens what a policy
can express, so each needs a grammar decision and a migration story for
existing files. None of them adds per-check cost, since all the work
happens at parse and prepare time.

### 7. Process arguments are not evaluated

`Policy::evaluate` destructures `Target::Process { command, args: _, cwd }`.
`allow command git` therefore allows `git -c core.pager=sh log`, verified.
`DOCUMENTATION.md` states this correctly, but the consequence deserves to
be stated louder: allowing `git`, `cargo`, `sh`, `python`, or `npm` is
allowing arbitrary code execution, because each accepts arguments that
execute other programs.

**Approach.** Add an optional argument predicate to command rules rather
than changing the meaning of existing rules, so old files keep working:

```text
allow command git
allow command git status, diff
```

Comma splitting already exists, so this reuses the existing shape. Exact
argv matching is honest and predictable; a glob or regex grammar here
would be a real complexity spike and is not recommended.

**Cost.** Zero per check beyond a string compare that only runs for
process requests. **Complexity.** Low in the parser, moderate in the
evaluator, because argv needs its own matcher and its own precedence
interaction with command-level deny.

### 8. Port is not evaluated

`Target::Network { host, port: _ }`, so `allow host api.github.com`
permits 443, 22, 5432, and 6379 alike, verified. Also worth noting that
`connect` returns a raw `TcpStream`, so once the single check passes the
caller can do anything at all with the socket.

**Approach.** Make port part of the host pattern grammar as an optional
suffix, `host:port`, defaulting to any port when absent. This keeps
existing `allow host api.github.com` files working and unchanged in
meaning.

**Cost.** Zero. **Complexity.** Low. The honest limit to document is that
host-based control is DNS-dependent and trivially defeated by a resolver
or a redirect; it is a policy expression, not egress filtering.

### 9. Environment

Verified: `execute("env", ...)` returned `SECRET_TOKEN=super-secret-value`
and the full `PATH`. There is no env rule kind at all, and command lookup
inherits `PATH`, so whoever controls `PATH` controls what `git` means.

**Approach.** Add `[process] env` allow and deny lists plus a fixed base
environment, then have `execute` call `env_clear` and set only what the
policy permits. This is a behavior change for existing policies, so it
needs a major version or an opt-in flag. Recommend opt-in first.

**Cost.** Zero per check. **Complexity.** Low in isolation, but it changes
`execute` semantics, so it is the item most likely to surprise.

### 10. Missing filesystem operations

The guarded set is read, write, delete, create, create_dir. There is no
`read_dir`, `rename`, `copy`, symlink creation, metadata read, truncate,
or append. `read_dir` is the notable omission, because a caller that can
list a directory can enumerate the entire filesystem with no policy check
at all. `rename` is the notable risk, because moving a file into an
allowed directory is a classic way to launder content past a write check.

**Approach.** Add `list`, `rename`, and `metadata` first, since they close
real gaps, and give `rename` both a source and a destination check.
Defer `copy` and symlink creation, which need a destination-side story
too. Keep each as a separate method rather than a trait, to match the
existing API shape and avoid a breaking redesign.

**Cost.** Zero for existing operations. **Complexity.** Moderate, mostly
because of path-pair semantics for `rename`.

### 11. `create_dir` is single level

Verified: `create_dir("./build/a/b")` returns
`io error: No such file or directory`. There is no `create_dir_all`, so
building a nested tree takes N calls, and each one is separately gated and
separately promptable under an `ask` rule.

**Approach.** Add `create_dir_all` that authorizes every prefix it
creates, or authorizes the deepest path and relies on default deny for
the rest. The first is more correct and costs one extra check per level.

**Cost.** Negligible. **Complexity.** Low.

## P3, robustness and ergonomics

### 12. `Nitera::load(".nitera")` always fails

The guard is `path.extension() == Some("nitera")`, and
`Path::new(".nitera").extension()` is `None`, because a leading dot reads
as a hidden file with no extension. Verified. This is the exact filename
in the README quick start, so the headline example cannot work.
`prod.nitera` loads fine.

**Approach.** Accept either a `nitera` extension or a file named exactly
`.nitera`. One line. **Cost.** Zero. **Complexity.** Trivial. Fix first,
before anything else, because it is a documentation bug in the shipped
README.

### 13. `HOME` required unconditionally

`resolve_runtime_path` calls `var_os("HOME")` and errors if it is unset,
even for a path with no `~` in it, and the operation then fails with
`Io` before any policy check runs. `DOCUMENTATION.md` notes it, but the
effect is that nitera is unusable in a minimal container and broken on
Windows, where `HOME` is often unset.

**Approach.** Require `HOME` only when the path or pattern actually
starts with `~`. This also removes an environment scan from the common
path, so it is a small latency win rather than a cost.

**Cost.** Slightly negative, a small win. **Complexity.** Low.

### 14. `Denied` carries no request

`NiteraOperationError::Denied` is a fieldless variant, while `Ask` carries
the full `NitraRequest`. That is an awkward asymmetry for audit logging,
since a denied operation leaves no record of what was attempted.

**Approach.** Add a new variant `DeniedRequest(NiteraRequest)` rather than
changing `Denied`, so existing `match` arms keep compiling, and have the
operations return the new variant. Alternatively add a `request()` accessor
returning `Option<&NitraRequest>` on the error type, which is additive and
breaks nothing.

**Cost.** Zero. **Complexity.** Low. Recommend the accessor, since it is
strictly additive.

### 15. No `#[non_exhaustive]`

None of the public enums carry it, so adding a variant later is a breaking
change. At roughly 25 lifetime downloads, the cost of adding it now is
near zero and the cost of deferring is a 2.0.

**Approach.** Add `#[non_exhaustive]` to `NiteraError`,
`NiteraOperationError`, `Decision`, `ParseError`, and `NiteraRequest`'s
associated enums. **Cost.** Zero. **Complexity.** Zero, but it *is*
technically breaking for downstream `match` expressions, so it belongs in
a clearly labelled release rather than a patch.

### 16. `Nitera` derives nothing

No `Debug`, so it cannot be logged or embedded in a struct that derives
`Debug`. `Clone` is also absent because of the `Arc<dyn ApprovalHandler>`
field, which is inherent and fine.

**Approach.** Hand-write a `Debug` impl that prints the root and whether a
handler is registered, and deliberately omits the handler. **Cost.** Zero.
**Complexity.** Trivial.

### 17. Silent never-match on normalization failure

`PreparedPath::new` returns `Tail::Never` when `normalize_pattern` fails,
and the public `PathPattern::matches_from` returns `false` on the same
failure. A `deny` rule in that state silently stops matching.

I suspected this was an exploitable fail-open via a `~` rule with `HOME`
unset at load, tested it, and **it does not reproduce**: `PreparedPolicy`
captures `HOME` at load and falls back to the unindexed evaluator whenever
it differs, which re-normalizes successfully and denies correctly. The
fallback masks the hazard by accident rather than by design.

**Approach.** Do not treat this as a live bug. Log a warning at load time
for any pattern that failed to normalize, and make the public
`matches_from` fail closed for `deny`-shaped use by returning a `Result`
in a future major. Low priority, worth a comment in the code so nobody
removes the `HOME` fallback without noticing what it is holding up.

### 18. macOS `/tmp` aliasing

`Nitera::load` canonicalizes the policy's parent into `root`, so a policy
at `/tmp/p/prod.nitera` gets root `/private/tmp/p`. A pattern written
relatively normalizes against the canonical root, but an already-normalized
absolute request path is borrowed as-is by the fast path in
`resolve_runtime_path`, so `/tmp/p/x` never matches
`/private/tmp/p/**`. This fails closed, so it is a confusion issue rather
than a bypass.

**Approach.** Document it, and note in the policy-authoring guide that
absolute patterns should be written in canonical form. **Complexity.** Low,
documentation only.

### 19. Smaller items

- `with_approval_handler` consumes `self`, so a shared `Nitera` cannot
  swap handlers. A `set_approval_handler(&mut self, ...)` alongside the
  builder method is a small, useful addition.
- No policy reload or watch. `load` returns a snapshot by design and that
  is documented, so treat it as a feature request, not a bug.
- Everything is blocking and there are no timeouts, which rules nitera out
  of an async runtime without a blocking pool. Adding async is a large
  surface and is not recommended at this stage.

## P4, documentation and benchmark integrity

- `examples/playground.nitersa` still contains `allow host api.github.com`
  directly above `deny host *`, so its own `allow` line is dead. The same
  trap was removed from the README during the 1.0.0 release but not from the
  example. Verified by running it.
- `README.md` presents 375 ns as the check cost generally. Once symlink
  resolution is in the path that number describes only `check()` on an
  already-normalized path, and the README should say so.
- `BENCHMARKS.md` is admirably honest about its own limits, including the
  single-workload-shape caveat. Add a row for the authorize-plus-resolve
  path when that harness exists.
- The `Nitera::load(".nitera")` failure in item 12 means the README quick
  start has never worked. Worth a note in the changelog when fixed.

## Suggested sequencing

Small, independent, individually reviewable and revertable PRs. Nothing
here needs to land as one change.

| PR | Contents | Risk | Latency |
|---|---|---|---|
| 1 | Item 12 (`.nitera` filename) | trivial | none |
| 2 | Item 6 (parser whitespace) | trivial | none |
| 3 | Items 4 and 5 (quoting) | low | none |
| 4 | Item 2 (case folding) | low | none |
| 5 | Item 13 (`HOME` only when needed) | low | small win |
| 6 | Item 16 (`Debug`) plus item 14 (error accessor) | trivial | none |
| 7 | Item 1 (symlink resolution) with a new bench harness | moderate | about +1 to 2 us per fs op |
| 8 | Items 11, 8, 7 (create_dir_all, port, argv) | low to moderate | none |
| 9 | Item 15 (`non_exhaustive`), labelled as breaking | none | none |
| 10 | Item 3 (Windows), needs a Windows CI runner | moderate | none |
| 11 | Items 9 and 10 (env, missing operations) | moderate to high | none |

Items 1 through 6 are all low risk and none of them move latency
meaningfully. Only item 7 does, and that is unavoidable for any real
symlink enforcement.

## Non-goals

Explicitly out of scope, so they are not mistaken for oversights:

- Descriptor-relative syscalls and true TOCTOU elimination. That is
  `cap-std`, with 21.7 million downloads, and duplicating it here would be
  a large permanent complexity burden for a crate this size.
- Full Unicode case folding and normalization. Needs locale data.
- Any global enforcement of `std::fs`. Not possible from a library.
- Async. Premature for the current API shape.

## Threat model, stated honestly

Nitera is an authorization and audit layer for code that opts in to it.
It is not a sandbox, and it is not a boundary against a hostile caller.

Items 1 and 2 are why that distinction matters concretely rather than
academically. On a default macOS setup, or any case-insensitive
filesystem, a narrow `allow` plus a broad `deny` policy can be bypassed
and the protected file will be returned. Item 2 needs nothing created on
disk, only a policy author writing `.SSH` where the caller writes
`.ssh`, which is an ordinary mistake rather than an attack.

So the accurate description of the crate today is: cooperative,
same-process code, with a human in the loop for ambiguous operations,
and a policy narrow enough that the remaining gaps do not matter for the
code you control. The existing "Current limits" section in `README.md`
gestures at this but understates it, since it describes the symlink
issue as a boundary "not currently handled" rather than a case where an
explicit `deny` does not fire.

Two things this document deliberately does not claim:

- That the fixes will make nitera safe against untrusted input. Symlink
  resolution narrows the traversal window; it does not close it.
  Descriptor-relative syscalls are the actual answer, and that is
  `cap-std`'s job.
- That any of this is novel. Symlink traversal past lexical path checks
  is CWE-59 and case-confusion path handling is CWE-178. Both are
  long-known classes, found by reading a day's worth of path code. The
  contribution here is that this particular crate has both, and that
  1.0.0 shipped with them.

## Reporting

Found something in the policy engine that is not in this document, or
disagree with a finding? Open an issue. Fix PRs against the items above
are welcome, and the ones marked as touching latency should say what
they measured.

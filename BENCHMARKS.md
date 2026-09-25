# Policy-check benchmarks

`Nitera::check()` still scans rules linearly. This compares the original
implementation at `07469ba` with the prepared matcher using the same machine,
working directory and benchmark harness.

## Results

Apple M5 Pro, 24 GiB RAM, macOS 27.0, Rust 1.98.1, optimized Cargo bench profile.

| Nonmatching rules | Total rules | Original median | Updated median | Speedup | p95 original → updated | p99 original → updated |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2 | 1,500 ns | 250 ns | 6.00× | 1,584 → 292 ns | 1,958 → 334 ns |
| 10 | 11 | 8,166 ns | 208 ns | 39.26× | 9,791 → 209 ns | 12,500 → 291 ns |
| 50 | 51 | 36,916 ns | 209 ns | 176.63× | 42,625 → 250 ns | 50,583 → 292 ns |
| 200 | 201 | 147,917 ns | 375 ns | 394.45× | 169,542 → 417 ns | 190,459 → 500 ns |
| 1,000 | 1,001 | 760,792 ns | 1,333 ns | 570.74× | 822,625 → 1,417 ns | 883,417 → 1,667 ns |

At 1,001 total rules, median latency fell from 760.792 µs to 1.333 µs.
The earlier version of this PR (`b2b3101`) measured 2.292 µs in the same
session, so the follow-up changes reduced that latency by a further 42%.

## Method

The harness in `benches/policy_check.rs` is unchanged. It generates N
nonmatching `allow read ./bench/dirN/**` rules followed by one matching
`allow read ./bench/target/**` rule. The request reads
`./bench/target/file.txt`, so the scan reaches the last rule.

Rows are labeled by nonmatching rules. The row labeled 1,000 contains 1,001
total rules. Each row uses a 1,000-call warmup and 100,000 individually timed
checks. Policy loading and request construction happen before timing starts.

The original executable was saved before changing the source. The previous
PR revision and the updated source were also built with:

```sh
cargo build --release --bench policy_check
```

All three executables ran from the same directory, in order: original,
previous PR revision, updated version. Running the saved executables directly
keeps policy base paths identical even when their sources are built in
separate checkouts. Each executable ran once in this final comparison.

To run the benchmark for a single checkout:

```sh
cargo bench --bench policy_check
```

## Changes and limits

Patterns are prepared at load time, while each request is resolved once.
Exact paths use equality checks. Literal prefixes use a component-boundary
check, with a cheap final-byte rejection before comparing a shared prefix.
Glob suffixes after the final `**` are matched from the end of the path,
avoiding repeated attempts at positions where they cannot match.

On Unix, relative paths are normalized without an intermediate joined buffer,
and already-normalized absolute paths can be borrowed. Other platforms keep
the existing path-joining behavior. HOME validation still runs before using
these fast paths; the source policy is retained for changes to HOME after load.

The scan order, Deny → Ask → Allow precedence, public API and zero-dependency
setup stay the same. Preparation adds load-time work and memory.

These timings cover one filesystem workload. General globs can still
backtrack, and the table does not establish performance for every policy,
resource type or path shape. It is not a claim of a universal lower bound.

Each implementation was measured once. Timer resolution and scheduling noise
matter at the low end: the updated 1-rule row was slower than the 10-rule row.
The table measures policy checks, not the filesystem operations they authorize.

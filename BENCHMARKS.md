# Policy-check benchmarks

`Nitera::check()` still scans rules linearly. This compares the original
implementation at `07469ba` with load-time path preparation, using the same
machine and benchmark harness for both builds.

## Results

Apple M5 Pro, 24 GiB RAM, macOS 27.0, Rust 1.98.1, optimized bench profile.

| Nonmatching rules | Total rules | Before median | After median | Speedup | p95 before → after | p99 before → after |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2 | 1,584 ns | 334 ns | 4.74× | 2,667 → 459 ns | 3,500 → 583 ns |
| 10 | 11 | 7,959 ns | 250 ns | 31.84× | 10,167 → 333 ns | 14,375 → 417 ns |
| 50 | 51 | 37,250 ns | 333 ns | 111.86× | 45,417 → 375 ns | 52,625 → 417 ns |
| 200 | 201 | 149,334 ns | 625 ns | 238.93× | 170,625 → 709 ns | 188,959 → 792 ns |
| 1,000 | 1,001 | 765,125 ns | 2,333 ns | 327.96× | 811,625 → 2,417 ns | 874,458 → 2,917 ns |

At 1,001 total rules, median latency dropped from 765.125 µs to 2.333 µs.
These are same-machine measurements; they should not be compared directly
with the older M2 results previously recorded here.

## Method

The harness in `benches/policy_check.rs` is unchanged. It generates N
nonmatching `allow read ./bench/dirN/**` rules followed by one matching
`allow read ./bench/target/**` rule. The request reads
`./bench/target/file.txt`, so the scan reaches the last rule.

The harness labels rows by the number of nonmatching rules. The row labeled
1,000 therefore contains 1,001 total rules. Each row uses a 1,000-call warmup
and 100,000 individually timed checks. Loading the policy and constructing
the request happen before timing starts.

The original benchmark executable was built and saved before changing the
source. After the changes were complete, it ran once from the same checkout
path used for the updated build. The full test suite then passed, followed
by one run of:

```sh
cargo bench --bench policy_check
```

Both builds used the same toolchain, profile, working directory and harness.

## Scope and limitations

Preparing patterns at load time removes repeated normalization and splitting
from the scan. Literal paths use equality checks; literal prefixes ending in
`/**` use a prefix check at a path-component boundary. Request normalization
happens once per check. The scan order and Deny → Ask → Allow precedence stay
the same.

Preparation uses additional memory and load time. The source policy is kept
so a change to HOME can use the original evaluator, preserving existing
home-relative rules and behavior when HOME is unset.

These measurements cover one filesystem workload. They do not establish
performance for arbitrary middle-`**` patterns, process or network policies,
policy loading, or memory use. General globs still require backtracking.

Each implementation was measured once. Timer resolution and scheduling noise
matter at the low end: the updated 1-rule row happened to be slower than the
10-rule row. The table measures policy checks, not the filesystem operations
they authorize.

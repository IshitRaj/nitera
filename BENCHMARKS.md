# Policy-check benchmarks

The prepared matcher uses a linear scan for small or unselective path rule
sets. Larger sets can use a sorted prefix index to find candidates, which are
then checked by the same matcher. This comparison uses the optimized linear
implementation at `66f6d23` as the baseline.

## Check latency

Apple M5 Pro, 24 GiB RAM, macOS 27.0, Rust 1.98.1, optimized Cargo bench profile.

| Total rules | Linear median | Indexed median | Speedup | Linear p95 | Indexed p95 | Linear p99 | Indexed p99 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 167 ns | 167 ns | 1.00× | 208 ns | 208 ns | 250 ns | 250 ns |
| 11 | 167 ns | 167 ns | 1.00× | 209 ns | 209 ns | 250 ns | 250 ns |
| 51 | 208 ns | 208 ns | 1.00× | 291 ns | 291 ns | 292 ns | 292 ns |
| 201 | 375 ns | 208 ns | 1.80× | 500 ns | 291 ns | 500 ns | 292 ns |
| 1,001 | 1,250 ns | 209 ns | 5.98× | 1,625 ns | 292 ns | 1,791 ns | 333 ns |

At 1,001 rules, the indexed version reduced median latency from 1.250 µs to
0.209 µs. These numbers compare against the already-optimized linear matcher,
not the original implementation's much slower timings.

The existing `benches/policy_check.rs` harness is unchanged. It creates N
nonmatching rules and one matching rule, then performs 1,000 warmup calls and
100,000 individually timed checks. Its `rule_count` labels exclude the final
matching rule; this table includes it. Loading and request construction are
outside the timed region.

Both versions were built with `cargo build --release --bench policy_check`.
Their saved executables ran from the same directory for five rounds, with the
order alternating between rounds. Each table entry is the median of that
statistic across the five runs; p95 and p99 are not pooled percentiles.

To run the benchmark for a checkout:

```sh
cargo bench --bench policy_check
```

The earlier original-to-linear comparison remains available in `66f6d23`.
Do not combine speedup ratios from separate sessions or machines.

## Index behavior

Each deny, ask and allow list has its own index. Process scopes use the same
path lookup. The first rule stays in place for a cheap early match; the rest
are sorted by their literal prefix, retaining order within each prefix group.
Lookup checks the relevant prefix lengths, binary-searches the matching groups,
and passes every candidate through the existing path matcher.

Rules with empty prefixes, such as `/**/private`, remain candidates. An exact
match needs the entire path; a glob prefix must end at a component boundary.
The index cannot omit a matching rule: its prefix length is recorded, its
matching prefix passes the boundary check, and its entire group is examined.

The index is used only for sets with at least 64 rules, at least eight distinct
prefixes, and no more than 16 distinct prefix lengths. Other sets retain the
scan. Broad wildcard groups can still require scanning many candidates, so
this does not guarantee logarithmic lookup for every policy.

HOME changes still use the original source evaluator. Missing HOME, non-UTF-8
paths, normalization, deny/ask/allow precedence and the public API retain their
existing behavior. No request results are cached and no dependencies were added.

## Loading and memory

For the 1,001-rule fixture, paired load measurements were 0.728 ms for the linear
version and 0.767 ms for the indexed version, about 5.4% more load time. At
10,001 rules they were 7.214 ms and 7.358 ms. These are medians of 31 alternating
measurements after warmup, including reading and parsing the policy.

At 1,001 rules, retained Rust heap allocations increased by 24 bytes, and the
Nitera value grew by 208 bytes. Peak requested Rust heap memory during loading
increased by about 54 KiB due to temporary sorting buffers. These measurements
exclude allocator bookkeeping and are not process RSS measurements.

## Limits

The standard harness covers a last-match filesystem workload. Other policies
can have different costs. Additional checks covered early matches, misses,
shared prefixes, exact paths and broad globs, but they do not establish a speedup
for every possible workload. Very small measurements are particularly sensitive
to timer resolution and scheduling. The table measures permission checks, not
the filesystem operations they authorize. Runtime measurements here are on macOS;
other platforms still need their own performance measurements.

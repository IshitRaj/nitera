use nitera::{Nitera, NiteraRequest, Operation};
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

/// Removes the fixture directory even if a measurement panics, so a failed
/// bench run does not leave a thousand files behind.
struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The policy extension, as one string so the write and the load cannot
/// disagree about the filename.
const POLICY_EXT: &str = "nitera";

/// Measures the cost of an authorized read, end to end.
///
/// `benches/policy_check.rs` measures `check()`, which is the advisory
/// lexical path and performs no filesystem I/O. A guarded `read` resolves
/// the request before authorizing it, so it costs a `canonicalize`. The
/// audit requires those two numbers to be reported separately rather than
/// letting the cheap one stand for the whole library.
fn main() {
    let dir = Fixture(std::env::temp_dir().join(format!("nitera-bench-{}", std::process::id())));
    let _ = fs::remove_dir_all(&dir.0);
    fs::create_dir_all(dir.0.join("target")).unwrap();

    for i in 0..1000 {
        fs::write(dir.0.join(format!("target/f{i}.txt")), b"x").unwrap();
    }

    let mut policy = String::from("[filesystem]\n");
    for i in 0..1000 {
        policy.push_str(&format!("allow read ./target/f{i}.txt\n"));
    }
    // One binding for the policy file, so the write and the load cannot
    // disagree about its name.
    let policy_path = dir.0.join(format!("bench.{POLICY_EXT}"));
    fs::write(&policy_path, &policy).unwrap();

    // `load` resolves every rule's literal anchor, so loading is now O(rules)
    // in filesystem calls rather than pure string work. Measure it, because it
    // is a cost this change adds and it is paid once, up front.
    let mut load_ns = Vec::with_capacity(20);
    for _ in 0..20 {
        let t0 = Instant::now();
        let _ = Nitera::load(&policy_path).unwrap();
        load_ns.push(t0.elapsed().as_nanos());
    }
    load_ns.sort_unstable();

    let nitera = Nitera::load(&policy_path).unwrap();
    let request = NiteraRequest::filesystem(Operation::Read, "./target/f0.txt");

    for _ in 0..1_000 {
        black_box(nitera.check(black_box(&request)));
    }

    // Fail loudly rather than silently timing the deny path.
    let target = dir.0.join("target/f0.txt");
    nitera
        .read(&target)
        .expect("the fixture read must be allowed");

    // Warm the read and resolution loops too, so the first timed sample does
    // not carry cold-start cost and skew the upper percentiles.
    for _ in 0..200 {
        let _ = nitera.read(&target);
        let _ = std::fs::canonicalize(&target);
    }

    let mut check_ns = Vec::with_capacity(20_000);
    for _ in 0..20_000 {
        let t0 = Instant::now();
        black_box(nitera.check(black_box(&request)));
        check_ns.push(t0.elapsed().as_nanos());
    }
    check_ns.sort_unstable();

    // The guarded read includes resolution, the policy check, and the
    // filesystem call itself, so it is dominated by syscalls rather than
    // by the policy engine.
    let mut read_ns = Vec::with_capacity(2_000);
    for _ in 0..2_000 {
        let t0 = Instant::now();
        // Result is discarded on purpose: the harness times the call, not
        // the outcome, and the fixture is known to be readable.
        let _ = black_box(nitera.read(black_box(&target)));
        read_ns.push(t0.elapsed().as_nanos());
    }
    read_ns.sort_unstable();

    // Resolution alone, for attribution. This is what the change adds.
    let mut resolve_ns = Vec::with_capacity(2_000);
    for _ in 0..2_000 {
        let t0 = Instant::now();
        let _ = black_box(std::fs::canonicalize(black_box(&target)));
        resolve_ns.push(t0.elapsed().as_nanos());
    }
    resolve_ns.sort_unstable();

    let pct = |v: &[u128], p: f64| v[((v.len() as f64 - 1.0) * p) as usize];

    println!("workload,median_ns,p95_ns,p99_ns");
    println!(
        "load_1000_rules,{},{},{}",
        pct(&load_ns, 0.50),
        pct(&load_ns, 0.95),
        pct(&load_ns, 0.99)
    );
    println!(
        "check_lexical_1000_rules,{},{},{}",
        pct(&check_ns, 0.50),
        pct(&check_ns, 0.95),
        pct(&check_ns, 0.99)
    );
    println!(
        "resolve_only,{},{},{}",
        pct(&resolve_ns, 0.50),
        pct(&resolve_ns, 0.95),
        pct(&resolve_ns, 0.99)
    );
    println!(
        "guarded_read_end_to_end,{},{},{}",
        pct(&read_ns, 0.50),
        pct(&read_ns, 0.95),
        pct(&read_ns, 0.99)
    );
}

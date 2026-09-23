use nitera::{
    Nitera,
    engine::request::{NiteraRequest, Operation},
};
use std::fs;
use std::hint::black_box;
use std::time::Instant;

fn make_policy(rule_count: usize) -> String {
    let mut s = String::from("[filesystem]\n");
    for i in 0..rule_count {
        s.push_str(&format!("allow read ./bench/dir{i}/**\n"));
    }
    s.push_str("allow read ./bench/target/**\n"); // the one that actually matches
    s
}

fn percentile(sorted_ns: &[u128], p: f64) -> u128 {
    sorted_ns[((sorted_ns.len() as f64 - 1.0) * p) as usize]
}

fn main() {
    println!("rule_count,median_ns,p95_ns,p99_ns");

    for &n in &[1usize, 10, 50, 200, 1000] {
        let path = format!("bench_{n}.nitera");
        fs::write(&path, make_policy(n)).unwrap();
        let nitera = Nitera::load(&path).unwrap();
        let req = NiteraRequest::filesystem(Operation::Read, "./bench/target/file.txt");

        for _ in 0..1_000 {
            black_box(nitera.check(black_box(&req)));
        }

        let mut samples = Vec::with_capacity(100_000);
        for _ in 0..100_000 {
            let t0 = Instant::now();
            black_box(nitera.check(black_box(&req)));
            samples.push(t0.elapsed().as_nanos());
        }
        samples.sort_unstable();
        println!(
            "{n},{},{},{}",
            percentile(&samples, 0.50),
            percentile(&samples, 0.95),
            percentile(&samples, 0.99)
        );
        fs::remove_file(&path).ok();
    }
}

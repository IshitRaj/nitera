use nitera::Nitera;
use std::time::Instant;

fn main() {
    const WARMUP: usize = 1_000;
    const SAMPLES: usize = 10_000;

    let root = std::env::temp_dir().join(format!(
        "nitera-guarded-read-bench-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let file = root.join("payload");
    std::fs::write(&file, b"cached synthetic payload").unwrap();
    let policy_path = root.join("policy.nitera");
    std::fs::write(&policy_path, "[filesystem]\nallow read ./payload\n").unwrap();
    let nitera = Nitera::load(&policy_path).unwrap();

    for _ in 0..WARMUP {
        assert_eq!(
            nitera.read("./payload").unwrap(),
            b"cached synthetic payload"
        );
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        assert_eq!(
            nitera.read("./payload").unwrap(),
            b"cached synthetic payload"
        );
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let percentile = |p: usize| samples[(samples.len() - 1) * p / 100];
    println!("workload,warmup,samples,p50_ns,p95_ns,p99_ns");
    println!(
        "guarded_read_cached_file,{WARMUP},{SAMPLES},{},{},{}",
        percentile(50),
        percentile(95),
        percentile(99)
    );
    std::fs::remove_dir_all(root).unwrap();
}

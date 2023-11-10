use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rad::{
    find_par::par_find,
    input_deterministic,
    params::{Bip39WordCount, MAX_INDEX},
    run_config::RunConfig,
    test_utils::_find_one,
};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("benchmarking");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(200)); // target "xyz" takes ~150 sec on Macbook Pro M2
    group.bench_function("benchy", |b| {
        b.iter(|| {
            black_box(
                // Fast targets: "d" (1.2), "t" (1.5), "u" (1.3), "z" (1.4)
                // _find_one(input_deterministic!("xyz")),
                par_find(1, input_deterministic!("xyz"), RunConfig::new(false, 0)),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

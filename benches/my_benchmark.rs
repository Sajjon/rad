use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rad::{
    find_par::par_find,
    input,
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
                // _find_one(input!("xyz").unwrap()),
                par_find(
                    input!("p").unwrap(), // RunConfig::new(false, 0, false, false),
                ),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

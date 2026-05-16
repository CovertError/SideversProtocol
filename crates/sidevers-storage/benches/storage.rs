//! Phase 1.F1: storage put/get baselines.
//!
//! Measures the cost of writing + reading content-addressed objects of
//! a few representative sizes. The ObjectStore is async, so each bench
//! drives a small Tokio runtime per iteration measurement (criterion
//! reports the steady-state cost).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use sidevers_storage::ObjectStore;
use tempfile::TempDir;
use tokio::runtime::Runtime;

fn bench_put(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("storage_put");
    for &size in &[64usize, 4096, 65_536] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            // Re-create a fresh store per iteration so put doesn't
            // benefit from any in-store dedup.
            b.iter_with_setup(
                || {
                    let dir = TempDir::new().unwrap();
                    let store = rt.block_on(ObjectStore::open(dir.path())).unwrap();
                    let bytes = vec![0xAB; size];
                    (dir, store, bytes)
                },
                |(dir, store, bytes)| {
                    let _ = rt.block_on(store.put(std::hint::black_box(bytes))).unwrap();
                    drop(dir);
                },
            );
        });
    }
    group.finish();
}

fn bench_get(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("storage_get");
    for &size in &[64usize, 4096, 65_536] {
        let dir = TempDir::new().unwrap();
        let store = rt.block_on(ObjectStore::open(dir.path())).unwrap();
        let hash = rt.block_on(store.put(vec![0xCD; size])).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let _bytes = rt.block_on(store.get(std::hint::black_box(&hash))).unwrap();
            });
        });
        // dir kept alive over the whole sub-iteration.
        drop(dir);
    }
    group.finish();
}

criterion_group!(storage, bench_put, bench_get);
criterion_main!(storage);

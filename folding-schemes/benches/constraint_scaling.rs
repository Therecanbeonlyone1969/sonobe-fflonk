//! Constraint Scaling Benchmark
//! 
//! Measures R1CS generation time across different circuit sizes.
//! Run: `cargo bench --bench constraint_scaling`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ark_bn254::Fr;
use ark_relations::gr1cs::ConstraintSystem;
use folding_schemes::bench_circuits::BenchCircuit;

fn benchmark_constraint_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("constraint_scaling");
    
    // Benchmark different constraint counts
    for size in [100, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("generate_constraints", size),
            &size,
            |b, &size| {
                let circuit = BenchCircuit::<Fr>::with_constraints(size);
                b.iter(|| {
                    let cs = ConstraintSystem::<Fr>::new_ref();
                    circuit.generate_constraints(cs.clone()).unwrap();
                    black_box(cs.num_constraints())
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_constraint_count_accuracy(c: &mut Criterion) {
    let mut group = c.benchmark_group("constraint_count");
    
    for (name, circuit) in [
        ("tiny", BenchCircuit::<Fr>::tiny()),
        ("small", BenchCircuit::<Fr>::small()),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| {
                let cs = ConstraintSystem::<Fr>::new_ref();
                circuit.generate_constraints(cs.clone()).unwrap();
                black_box(cs.num_constraints())
            });
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_constraint_generation,
    benchmark_constraint_count_accuracy,
);
criterion_main!(benches);

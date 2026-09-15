use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use sppuffin::fn_impl::{fn_immutable_byte_array_length, fn_new_immutable_byte_array};


fn test_jni() {
    let a = fn_new_immutable_byte_array().unwrap();
    fn_immutable_byte_array_length(&a).unwrap();
}
fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Connexion simple JNI", |b| b.iter(|| test_jni()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
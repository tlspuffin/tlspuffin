use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sppuffin::swisspost::*;


fn test_jni() {
    let a = fn_new_immutable_byte_array(black_box(&fn_seq_5().unwrap())).unwrap();
    fn_immutable_byte_array_length(&a).unwrap();
}
fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Connexion simple JNI", |b| b.iter(|| test_jni()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
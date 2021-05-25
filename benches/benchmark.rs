use criterion::{criterion_group, criterion_main, Criterion};
use ring::hmac::{Key, HMAC_SHA256};
use std::any::Any;
use tlspuffin::{make_dynamic, op_hmac256};

fn benchmark_dynamic(c: &mut Criterion) {
    let mut group = c.benchmark_group("op_hmac256");

    group.bench_function("op_hmac256 static", |b| {
        b.iter(|| {
            let key_data = [0; 256];
            let key = Key::new(HMAC_SHA256, &key_data);
            let data = "test".as_bytes().to_vec();
            op_hmac256(&key, &data)
        })
    });

    group.bench_function("op_hmac256 dyn", |b| {
        b.iter(|| {
            let key_data = [0; 256];
            let key = Key::new(HMAC_SHA256, &key_data);
            let data = "test".as_bytes().to_vec();
            let (_, dynamic_fn) = make_dynamic(&op_hmac256);
            let args: Vec<Box<dyn Any>> = vec![Box::new(key), Box::new(data)];
            dynamic_fn(&args)
        })
    });

    group.finish()
}

criterion_group!(benches, benchmark_dynamic);
criterion_main!(benches);
